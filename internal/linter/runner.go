package linter

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/evaluator"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
)

func Run(cfg Config, w io.Writer) error {
	applyDefaults(&cfg)
	if err := cfg.Validate(); err != nil {
		return err
	}
	var cleanups cleanupStack
	defer cleanups.Close()

	diagnostics := diagnosticsWriter(cfg, w)
	reg := operator.DefaultRegistry()

	// Load policies and validate that every rule is executable by the same
	// registry that will evaluate it. YAML shape validation alone cannot catch
	// misspelled or unavailable operators.
	policies, err := loadPolicies(cfg.PolicyPaths, reg)
	if err != nil {
		return err
	}

	inputs, err := acquireInputs(cfg, diagnostics, &cleanups)
	if err != nil {
		return err
	}
	results := evaluator.Evaluate(buildSubjects(cfg, inputs, policies, reg, diagnostics), reg)
	if len(results) == 0 {
		return fmt.Errorf("no loaded policy applies to the supplied input")
	}

	return outputResults(cfg, results, w)
}

// lintInputs is everything a run evaluates, after loading, chain building
// and automatic retrieval. chain is nil without certificate input.
type lintInputs struct {
	chain   []*cert.Info
	issuers []*cert.Info
	crls    []*crl.Info
	ocsps   []*ocsp.Info
}

func acquireInputs(cfg Config, diagnostics io.Writer, cleanups *cleanupStack) (lintInputs, error) {
	var inputs lintInputs
	var err error
	if inputs.crls, err = loadCRLs(cfg.CRLPath); err != nil {
		return lintInputs{}, err
	}
	if inputs.ocsps, err = loadOCSPs(cfg.OCSPPath); err != nil {
		return lintInputs{}, err
	}

	// Issuers support chain building and CRL/OCSP signature verification.
	issuers, issuerCleanup, err := loadIssuersIfProvided(cfg)
	cleanups.Add(issuerCleanup)
	if err != nil {
		return lintInputs{}, err
	}
	inputs.issuers = issuers

	if !cfg.hasCertificateInput() {
		if len(inputs.crls) == 0 && len(inputs.ocsps) == 0 {
			return lintInputs{}, fmt.Errorf("no certificates, CRLs, or OCSP responses provided")
		}
		return inputs, nil
	}

	certs, certCleanup, err := loadCertificates(cfg)
	cleanups.Add(certCleanup)
	if err != nil {
		return lintInputs{}, err
	}
	if inputs.chain, err = buildCertificateChain(cfg, certs, issuers, diagnostics); err != nil {
		return lintInputs{}, err
	}

	if cfg.AutoValidate && !cfg.NoAutoCRL {
		inputs.crls = append(inputs.crls, fetchAutoCRLs(cfg, inputs.chain, diagnostics)...)
	}
	if cfg.AutoValidate && !cfg.NoAutoOCSP {
		inputs.ocsps = append(inputs.ocsps, fetchAutoOCSPs(cfg, inputs.chain, diagnostics)...)
	}
	return inputs, nil
}

func buildCertificateChain(cfg Config, certs, issuers []*cert.Info, w io.Writer) ([]*cert.Info, error) {
	allCerts := make([]*cert.Info, 0, len(certs)+len(issuers))
	allCerts = append(allCerts, certs...)
	allCerts = append(allCerts, issuers...)
	if len(allCerts) == 0 {
		return nil, fmt.Errorf("no certificates available to build a chain")
	}

	if cfg.AutoValidate && !cfg.NoAutoChain {
		allCerts = append(climbChains(cfg, certs, allCerts, w), issuers...)
	}

	chain, err := cert.BuildChain(allCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate chain: %w", err)
	}
	return chain, nil
}

// buildSubjects returns every evaluated input in output order: the chain,
// then OCSP responses, then CRLs. Without certificates, CRLs and OCSP
// responses are evaluated on their own.
func buildSubjects(
	cfg Config,
	inputs lintInputs,
	policies []policy.Policy,
	reg *operator.Registry,
	w io.Writer,
) []evaluator.Subject {
	if inputs.chain == nil {
		var subjects []evaluator.Subject
		if len(inputs.crls) > 0 {
			subjects = append(subjects, evaluator.CRLSubjects(evaluator.Context{
				Policies:       policies,
				Registry:       reg,
				CRLs:           inputs.crls,
				Chain:          inputs.issuers,
				ValidationTime: cfg.ValidationTime,
			})...)
		}
		if len(inputs.ocsps) > 0 {
			subjects = append(subjects, evaluator.OCSPSubjects(evaluator.Context{
				Policies:       policies,
				Registry:       reg,
				OCSPs:          inputs.ocsps,
				ValidationTime: cfg.ValidationTime,
			})...)
		}
		return subjects
	}

	evalCtx := evaluator.PrepareCRLIssuers(evaluator.Context{
		Policies:            policies,
		Registry:            reg,
		CRLs:                inputs.crls,
		OCSPs:               inputs.ocsps,
		Chain:               inputs.chain,
		RevocationRequested: crlRevocationRequested(cfg),
		ValidationTime:      validationTime(cfg),
		ApplicationPurpose:  cfg.ApplicationPurpose,
		CRLResolveTimeout:   crlResolveTimeout(cfg),
		CRLResolveMaxDepth:  crlResolveMaxDepth(cfg),
		CRLResolveWarn:      w,
	})
	subjects := evaluator.ChainSubjects(evalCtx)
	if len(inputs.ocsps) > 0 {
		subjects = append(subjects, evaluator.OCSPSubjects(evalCtx)...)
	}
	if len(inputs.crls) > 0 {
		subjects = append(subjects, evaluator.CRLSubjects(evalCtx)...)
	}
	return subjects
}

func loadPolicies(paths []string, reg *operator.Registry) ([]policy.Policy, error) {
	var policies []policy.Policy
	for _, path := range paths {
		isDir, err := isDirectory(path)
		if err != nil {
			return nil, fmt.Errorf("checking policy path %s: %w", path, err)
		}

		if isDir {
			p, err := policy.ParseDirWithRegistry(path, reg)
			if err != nil {
				return nil, fmt.Errorf("failed to parse policy directory %s: %w", path, err)
			}
			policies = append(policies, p...)
		} else {
			p, err := policy.ParseFileWithRegistry(path, reg)
			if err != nil {
				return nil, fmt.Errorf("failed to parse policy file %s: %w", path, err)
			}
			policies = append(policies, p)
		}
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("no policy files found")
	}
	for _, parsed := range policies {
		if len(parsed.Rules) == 0 {
			return nil, fmt.Errorf("policy %s contains no rules", parsed.ID)
		}
	}
	return policies, nil
}

func loadCRLs(path string) ([]*crl.Info, error) {
	if path == "" {
		return nil, nil
	}
	crls, err := crl.GetCRLs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load CRLs: %w", err)
	}
	return crls, nil
}

func loadOCSPs(path string) ([]*ocsp.Info, error) {
	if path == "" {
		return nil, nil
	}
	ocsps, err := ocsp.GetOCSPs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load OCSP responses: %w", err)
	}
	return ocsps, nil
}

func loadIssuersIfProvided(cfg Config) ([]*cert.Info, func(), error) {
	if !cfg.hasIssuerInput() {
		return nil, nil, nil
	}
	return loadIssuers(cfg)
}

// climbChains extends each leaf towards a root via CA Issuers URLs, falling
// back to the supplied pool when a certificate has none. Certificates found
// while climbing join the pool for later leaves.
func climbChains(cfg Config, leaves, known []*cert.Info, w io.Writer) []*cert.Info {
	pool := append([]*cert.Info{}, known...)
	poolSet := cert.NewCertificateSet(cert.CertsFromInfos(pool)...)
	var climbed []*cert.Info
	for _, leaf := range leaves {
		if leaf.Cert == nil {
			continue
		}
		chain := cert.ClimbChainWithPool([]*cert.Info{leaf}, pool, cfg.CertTimeout, cfg.MaxChainDepth, w)
		climbed = append(climbed, chain...)
		for _, info := range chain {
			if info == nil || !poolSet.Add(info.Cert) {
				continue
			}
			pool = append(pool, info)
		}
	}
	return climbed
}

func fetchAutoCRLs(cfg Config, chain []*cert.Info, w io.Writer) []*crl.Info {
	fetchSession := crl.NewFetchSession(crl.FetchConfig{
		Timeout: crlResolveTimeout(cfg),
	})
	return fetchSession.FetchForChain(chain, w)
}

func fetchAutoOCSPs(cfg Config, chain []*cert.Info, w io.Writer) []*ocsp.Info {
	nonceOpts := buildNonceOptions(cfg)
	autoOCSPs, errs := ocsp.FetchForChain(chain, cfg.OCSPTimeout, nonceOpts)
	for _, err := range errs {
		_, _ = fmt.Fprintf(w, "Warning: auto OCSP fetch failed for %v\n", err)
	}
	if cfg.Verbosity >= 2 {
		for _, ocspInfo := range autoOCSPs {
			printOCSPResponseDebug(w, ocspInfo, nonceOpts)
		}
	}
	return autoOCSPs
}

// diagnosticsWriter returns the stream for acquisition warnings. Without an
// explicit stream, machine-readable output discards them so the result stays
// a single valid document.
func diagnosticsWriter(cfg Config, w io.Writer) io.Writer {
	switch {
	case cfg.Diagnostics != nil:
		return cfg.Diagnostics
	case cfg.OutputFmt == output.FormatJSON || cfg.OutputFmt == output.FormatYAML:
		return io.Discard
	default:
		return w
	}
}

func outputResults(cfg Config, results []policy.Result, w io.Writer) error {
	outputOpts := output.Options{
		ShowPassed:  cfg.Verbosity >= 1,
		ShowFailed:  true,
		ShowSkipped: cfg.Verbosity >= 2,
		ShowMeta:    cfg.ShowMeta,
	}

	lintOutput := output.FromPolicyResults(results)
	lintOutput = output.FilterRules(lintOutput, outputOpts)

	formatter := output.GetFormatter(cfg.OutputFmt, outputOpts)
	return formatter.Format(w, lintOutput)
}

func validationTime(cfg Config) time.Time {
	if !cfg.ValidationTime.IsZero() {
		return cfg.ValidationTime
	}
	return time.Now()
}

func crlResolveTimeout(cfg Config) time.Duration {
	if cfg.CertTimeout > 0 {
		return cfg.CertTimeout
	}
	return cfg.OCSPTimeout
}

func crlResolveMaxDepth(cfg Config) int {
	if cfg.MaxChainDepth > 0 {
		return cfg.MaxChainDepth
	}
	return 10
}

func crlRevocationRequested(cfg Config) bool {
	return cfg.CRLPath != "" || (cfg.AutoValidate && !cfg.NoAutoCRL)
}

func applyDefaults(cfg *Config) {
	if cfg.IssuerPath != "" && !containsString(cfg.IssuerPaths, cfg.IssuerPath) {
		cfg.IssuerPaths = append([]string{cfg.IssuerPath}, cfg.IssuerPaths...)
	}
	if cfg.CertTimeout <= 0 {
		cfg.CertTimeout = 10 * time.Second
	}
	if cfg.OCSPTimeout <= 0 {
		cfg.OCSPTimeout = 5 * time.Second
	}
	if cfg.OutputFmt == "" {
		cfg.OutputFmt = output.FormatText
	}

	// Auto-validate defaults
	if cfg.AutoValidate {
		if cfg.MaxChainDepth <= 0 {
			cfg.MaxChainDepth = 10
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func isDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

func buildNonceOptions(cfg Config) *ocsp.NonceOptions {
	return &ocsp.NonceOptions{
		Length:   cfg.OCSPNonceLength,
		Value:    cfg.OCSPNonceValue,
		Disabled: cfg.NoOCSPNonce,
		Hash:     cfg.OCSPHashAlgorithm,
	}
}
