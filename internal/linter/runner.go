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

	var results []policy.Result

	// Load CRLs if provided
	crls, err := loadCRLs(cfg.CRLPath)
	if err != nil {
		return err
	}

	// Load OCSP if provided
	ocsps, err := loadOCSPs(cfg.OCSPPath)
	if err != nil {
		return err
	}

	// Load issuers for CRL/OCSP signature verification
	issuers, issuerCleanup, err := loadIssuersIfProvided(cfg)
	cleanups.Add(issuerCleanup)
	if err != nil {
		return err
	}

	switch {
	case cfg.hasCertificateInput():
		var certCleanup func()
		results, certCleanup, err = processCertificates(cfg, policies, reg, crls, ocsps, issuers, diagnostics)
		cleanups.Add(certCleanup)
		if err != nil {
			return err
		}
	case len(crls) > 0:
		results = evaluator.CRLOnly(policies, reg, crls, issuers)
	case len(ocsps) > 0:
		results = evaluator.OCSPOnly(policies, reg, ocsps)
	default:
		return fmt.Errorf("no certificates, CRLs, or OCSP responses provided")
	}
	if len(results) == 0 {
		return fmt.Errorf("no loaded policy applies to the supplied input")
	}

	// Output results
	return outputResults(cfg, results, w)
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

func processCertificates(cfg Config, policies []policy.Policy, reg *operator.Registry, crls []*crl.Info, ocsps []*ocsp.Info, issuers []*cert.Info, w io.Writer) ([]policy.Result, func(), error) {
	// Load leaf certificates
	certs, cleanup, err := loadCertificates(cfg)
	if err != nil {
		return nil, cleanup, err
	}

	allCerts := make([]*cert.Info, 0, len(certs)+len(issuers))
	allCerts = append(allCerts, certs...)
	allCerts = append(allCerts, issuers...)
	if len(allCerts) == 0 {
		return nil, cleanup, fmt.Errorf("no certificates available to build a chain")
	}

	if cfg.AutoValidate && !cfg.NoAutoChain {
		allCerts = append(climbChains(cfg, certs, allCerts, w), issuers...)
	}

	chain, err := cert.BuildChain(allCerts)
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to build certificate chain: %w", err)
	}

	if cfg.AutoValidate && !cfg.NoAutoCRL {
		crls = append(crls, fetchAutoCRLs(cfg, chain, w)...)
	}
	if cfg.AutoValidate && !cfg.NoAutoOCSP {
		ocsps = append(ocsps, fetchAutoOCSPs(cfg, chain, w)...)
	}

	evalCtx := evaluator.Context{
		Policies:            policies,
		Registry:            reg,
		CRLs:                crls,
		OCSPs:               ocsps,
		Chain:               chain,
		RevocationRequested: crlRevocationRequested(cfg),
		ValidationTime:      time.Now(),
		ApplicationPurpose:  cfg.ApplicationPurpose,
		CRLResolveTimeout:   crlResolveTimeout(cfg),
		CRLResolveMaxDepth:  crlResolveMaxDepth(cfg),
		CRLResolveWarn:      w,
	}
	evalCtx = evaluator.PrepareCRLIssuers(evalCtx)
	results := evaluator.Chain(evalCtx)

	if len(ocsps) > 0 {
		results = append(results, evaluator.OCSP(evalCtx)...)
	}

	if len(crls) > 0 {
		results = append(results, evaluator.CRL(evalCtx)...)
	}

	return results, cleanup, nil
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
