package linter

import (
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/evaluator"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	pathpkg "github.com/cavoq/PCL/internal/path"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/source"
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
	results := evaluator.Evaluate(buildSubjects(cfg, inputs, policies, reg), reg)
	if len(results) == 0 {
		return fmt.Errorf("no loaded policy applies to the supplied input")
	}

	if err := outputResults(cfg, results, w); err != nil {
		return err
	}
	if failed := failedRulesAtOrAbove(results, cfg.FailOn); failed > 0 {
		return fmt.Errorf("%d failed rule(s) with severity %s or higher", failed, cfg.FailOn)
	}
	return nil
}

// FailOnNone is the FailOn value that never fails a run on its results.
const FailOnNone = "none"

// failOnRanks orders the FailOn thresholds; rule severities share the ranks.
// Zero never fails a run.
var failOnRanks = map[string]int{
	"":                   0,
	FailOnNone:           0,
	rule.SeverityInfo:    1,
	rule.SeverityWarning: 2,
	rule.SeverityError:   3,
}

// failedRulesAtOrAbove counts the failed rules whose severity ranks at or
// above threshold.
func failedRulesAtOrAbove(results []policy.Result, threshold string) int {
	minimum := failOnRanks[threshold]
	if minimum == 0 {
		return 0
	}
	failed := 0
	for _, result := range results {
		for _, ruleResult := range result.Results {
			if ruleResult.Verdict == rule.VerdictFail && failOnRanks[ruleResult.Severity] >= minimum {
				failed++
			}
		}
	}
	return failed
}

// lintInputs is everything a run evaluates, after loading, chain building
// and automatic retrieval. chain is nil without certificate input.
type lintInputs struct {
	chain []*cert.Info
	// certificates holds every supplied, climbed or downloaded certificate.
	certificates []*cert.Info
	issuers      []*cert.Info
	trustAnchors []*cert.Info
	crls         []*crl.Info
	ocsps        []*ocsp.Info
}

func acquireInputs(cfg Config, diagnostics io.Writer, cleanups *cleanupStack) (lintInputs, error) {
	var inputs lintInputs
	var err error
	if inputs.crls, err = loadCRLs(cfg.CRLPath, diagnostics); err != nil {
		return lintInputs{}, err
	}
	if inputs.ocsps, err = loadOCSPs(cfg.OCSPPath, diagnostics); err != nil {
		return lintInputs{}, err
	}

	// Issuers support chain building and CRL/OCSP signature verification.
	issuers, issuerCleanup, err := loadIssuersIfProvided(cfg, diagnostics)
	cleanups.Add(issuerCleanup)
	if err != nil {
		return lintInputs{}, err
	}
	inputs.issuers = issuers
	if inputs.trustAnchors, err = loadTrustAnchors(cfg.TrustAnchorPaths, diagnostics); err != nil {
		return lintInputs{}, err
	}

	if !cfg.hasCertificateInput() {
		if len(inputs.crls) == 0 && len(inputs.ocsps) == 0 {
			return lintInputs{}, fmt.Errorf("no CRL or OCSP response files found in the given paths")
		}
		cert.ResolveInheritedDSAParameters(append(slices.Clone(inputs.issuers), inputs.trustAnchors...))
		return inputs, nil
	}

	certs, certCleanup, err := loadCertificates(cfg, diagnostics)
	cleanups.Add(certCleanup)
	if err != nil {
		return lintInputs{}, err
	}
	if inputs.chain, inputs.certificates, err = buildCertificateChain(
		cfg,
		certs,
		issuers,
		inputs.trustAnchors,
		diagnostics,
	); err != nil {
		return lintInputs{}, err
	}

	if cfg.AutoValidate && !cfg.NoAutoCRL {
		inputs.crls = append(inputs.crls, fetchAutoCRLs(cfg, inputs.chain, diagnostics)...)
	}
	if cfg.AutoValidate && !cfg.NoAutoOCSP {
		inputs.ocsps = append(inputs.ocsps, fetchAutoOCSPs(cfg, inputs.chain, diagnostics)...)
	}
	if cfg.climbsCAIssuers() {
		inputs.certificates = append(inputs.certificates, discoverSignerIssuers(cfg, inputs, diagnostics)...)
		// Signer issuers can supply parameters to certificates that had no
		// verifying issuer during chain building.
		cert.ResolveInheritedDSAParameters(inputs.certificates)
	}
	return inputs, nil
}

// discoverSignerIssuers downloads through CA Issuers URLs the certificates
// needed to verify CRL signers and delegated OCSP responders that the known
// certificates cannot. Evaluation itself never downloads; it finds these
// certificates among the known ones.
func discoverSignerIssuers(cfg Config, inputs lintInputs, w io.Writer) []*cert.Info {
	known := cert.NewCertificateSet(cert.CertsFromInfos(inputs.chain)...)
	for _, info := range inputs.certificates {
		known.Add(info.Cert)
	}
	candidates := append(append([]*cert.Info(nil), inputs.chain...), inputs.certificates...)
	var found []*cert.Info
	add := func(certificate *x509.Certificate) {
		if certificate != nil && known.Add(certificate) {
			info := &cert.Info{Cert: certificate, Source: source.Info{Type: source.Downloaded}}
			found = append(found, info)
			candidates = append(candidates, info)
		}
	}

	for _, crlInfo := range inputs.crls {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}
		for _, certificate := range crl.ResolveIssuerCerts(candidates, crlInfo.CRL, cfg.CertTimeout, cfg.MaxChainDepth, w) {
			add(certificate)
		}
	}
	for _, ocspInfo := range inputs.ocsps {
		signer, err := ocspInfo.ResponderCertificate()
		if err != nil || signer == nil {
			continue
		}
		for _, info := range ocsp.DiscoverSignerIssuers(signer, inputs.chain, cfg.CertTimeout, cfg.MaxChainDepth, w) {
			add(info.Cert)
		}
	}
	return found
}

// buildCertificateChain returns the evaluated chain and every certificate
// that was available to build it.
func buildCertificateChain(
	cfg Config,
	certs, issuers, trustAnchors []*cert.Info,
	w io.Writer,
) ([]*cert.Info, []*cert.Info, error) {
	allCerts := make([]*cert.Info, 0, len(certs)+len(issuers)+len(trustAnchors))
	allCerts = append(allCerts, certs...)
	allCerts = append(allCerts, issuers...)
	allCerts = append(allCerts, trustAnchors...)
	if len(allCerts) == 0 {
		return nil, nil, fmt.Errorf("no certificates available to build a chain")
	}

	if cfg.climbsCAIssuers() {
		allCerts = append(climbChains(cfg, certs, allCerts, w), issuers...)
		allCerts = append(allCerts, trustAnchors...)
	}
	// Issuer selection verifies signatures, so inherited DSA parameters are
	// resolved before any path is built.
	cert.ResolveInheritedDSAParameters(allCerts)

	var (
		chain []*cert.Info
		err   error
	)
	if len(trustAnchors) > 0 {
		construction, constructionErr := pathpkg.Construct(certs, allCerts, trustAnchors, cfg.MaxChainDepth)
		if constructionErr != nil {
			return nil, nil, fmt.Errorf("failed to construct certificate path: %w", constructionErr)
		}
		if construction.Truncated {
			_, _ = fmt.Fprintln(w, "Warning: no certificate path reaches a trust anchor; the search for the "+
				"longest unanchored path stopped at its work limit, so the evaluated chain may not be the longest")
		}
		chain = construction.Chain
	} else {
		chain, err = cert.BuildChainFor(certs, allCerts)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build certificate chain: %w", err)
	}
	for _, target := range certs {
		inChain := slices.ContainsFunc(chain, func(member *cert.Info) bool {
			return cert.SameCertificate(member.Cert, target.Cert)
		})
		if !inChain {
			_, _ = fmt.Fprintf(w, "Warning: %s is not part of the evaluated certificate chain and is not linted\n", target.FilePath)
		}
	}
	return chain, allCerts, nil
}

// buildSubjects returns every evaluated input in output order: the chain,
// then OCSP responses, then CRLs. Without certificates, CRLs and OCSP
// responses are evaluated on their own.
func buildSubjects(
	cfg Config,
	inputs lintInputs,
	policies []policy.Policy,
	reg *operator.Registry,
) []evaluator.Subject {
	now := validationTime(cfg)
	if inputs.chain == nil {
		var subjects []evaluator.Subject
		if len(inputs.crls) > 0 {
			subjects = append(subjects, evaluator.CRLSubjects(evaluator.Context{
				Policies:       policies,
				Registry:       reg,
				CRLs:           inputs.crls,
				Chain:          inputs.issuers,
				ValidationTime: now,
			})...)
		}
		if len(inputs.ocsps) > 0 {
			subjects = append(subjects, evaluator.OCSPSubjects(evaluator.Context{
				Policies:       policies,
				Registry:       reg,
				OCSPs:          inputs.ocsps,
				ValidationTime: now,
			})...)
		}
		return subjects
	}

	evalCtx := evaluator.Context{
		Policies:                policies,
		Registry:                reg,
		CRLs:                    inputs.crls,
		OCSPs:                   inputs.ocsps,
		Chain:                   inputs.chain,
		Certificates:            inputs.certificates,
		RevocationRequested:     crlRevocationRequested(cfg),
		ValidationTime:          now,
		ApplicationPurpose:      cfg.ApplicationPurpose,
		CertificatePolicyInputs: cfg.CertificatePolicyInputs,
		TrustAnchors:            inputs.trustAnchors,
		MaximumPathLength:       configuredMaximumPathLength(cfg),
		PathRevocation:          cfg.PathRevocation,
	}
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

func loadCRLs(path string, w io.Writer) ([]*crl.Info, error) {
	if path == "" {
		return nil, nil
	}
	crls, err := crl.GetCRLs(path, w)
	if err != nil {
		return nil, fmt.Errorf("failed to load CRLs: %w", err)
	}
	return crls, nil
}

func loadOCSPs(path string, w io.Writer) ([]*ocsp.Info, error) {
	if path == "" {
		return nil, nil
	}
	ocsps, err := ocsp.GetOCSPs(path, w)
	if err != nil {
		return nil, fmt.Errorf("failed to load OCSP responses: %w", err)
	}
	return ocsps, nil
}

func loadIssuersIfProvided(cfg Config, w io.Writer) ([]*cert.Info, func(), error) {
	if !cfg.hasIssuerInput() {
		return nil, nil, nil
	}
	return loadIssuers(cfg, w)
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
		Timeout: cfg.CertTimeout,
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
		ShowDetails: cfg.ShowDetails,
		Color:       cfg.Color,
	}

	formatter := output.GetFormatter(cfg.OutputFmt, outputOpts)
	return formatter.Format(w, output.FromPolicyResults(results))
}

func validationTime(cfg Config) time.Time {
	if !cfg.ValidationTime.IsZero() {
		return cfg.ValidationTime
	}
	return time.Now()
}

func crlRevocationRequested(cfg Config) bool {
	return cfg.CRLPath != "" || (cfg.AutoValidate && !cfg.NoAutoCRL)
}

func configuredMaximumPathLength(cfg Config) *int {
	if !cfg.MaximumPathLengthConfigured {
		return nil
	}
	maximum := cfg.MaximumPathLength
	return &maximum
}

// Defaults for unset Config fields; the command line flags use them too.
const (
	DefaultCertTimeout   = 10 * time.Second
	DefaultOCSPTimeout   = 5 * time.Second
	DefaultMaxChainDepth = 10
)

func applyDefaults(cfg *Config) {
	if cfg.CertTimeout <= 0 {
		cfg.CertTimeout = DefaultCertTimeout
	}
	if cfg.OCSPTimeout <= 0 {
		cfg.OCSPTimeout = DefaultOCSPTimeout
	}
	if cfg.MaxChainDepth <= 0 {
		cfg.MaxChainDepth = DefaultMaxChainDepth
	}
	if cfg.OutputFmt == "" {
		cfg.OutputFmt = output.FormatText
	}
	if !cfg.MaximumPathLengthConfigured && cfg.MaximumPathLength > 0 {
		cfg.MaximumPathLengthConfigured = true
	}
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
