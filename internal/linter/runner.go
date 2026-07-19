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
	var cleanups cleanupStack
	defer cleanups.Close()

	diagnostics := cfg.Diagnostics
	if diagnostics == nil && (cfg.OutputFmt == "json" || cfg.OutputFmt == "yaml") {
		// Keep machine-readable output a single valid document. Diagnostic
		// acquisition warnings belong on a separate channel.
		diagnostics = io.Discard
	} else if diagnostics == nil {
		diagnostics = w
	}

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

	// Process certificates if provided
	hasCert := cfg.CertPath != "" || len(cfg.CertURLs) > 0
	hasIssuer := len(cfg.IssuerPaths) > 0 || len(cfg.IssuerURLs) > 0

	// Load issuers for CRL/OCSP signature verification
	issuers, issuerCleanup, err := loadIssuersIfProvided(cfg, hasIssuer)
	cleanups.Add(issuerCleanup)
	if err != nil {
		return err
	}

	if hasCert {
		var certCleanup func()
		results, certCleanup, err = processCertificates(cfg, policies, reg, crls, ocsps, issuers, diagnostics)
		cleanups.Add(certCleanup)
		if err != nil {
			return err
		}
	} else if len(crls) > 0 {
		results = evaluator.CRLOnly(policies, reg, crls, issuers)
	} else if len(ocsps) > 0 {
		results = evaluator.OCSPOnly(policies, reg, ocsps)
	} else {
		return fmt.Errorf("no certificates, CRLs, or OCSP responses provided")
	}
	if len(results) == 0 {
		return fmt.Errorf("no loaded policy applies to the supplied input")
	}

	// Output results
	return outputResults(cfg, results, w)
}

func loadPolicies(paths []string, reg *operator.Registry) ([]policy.Policy, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one policy path is required")
	}

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

func loadIssuersIfProvided(cfg Config, hasIssuer bool) ([]*cert.Info, func(), error) {
	if !hasIssuer {
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

	// Build chain
	allCerts := append(certs, issuers...)
	if len(allCerts) == 0 {
		return nil, cleanup, fmt.Errorf("no certificates available to build a chain")
	}

	// Auto-validate: climb chain via CA Issuers URLs (pool fallback when no CaIssuers)
	if cfg.AutoValidate && !cfg.NoAutoChain {
		pool := append([]*cert.Info{}, allCerts...)
		var climbedCerts []*cert.Info
		for _, c := range certs {
			if c.Cert == nil {
				continue
			}
			miniChain := []*cert.Info{c}
			miniChain = cert.ClimbChainWithPool(miniChain, pool, cfg.CertTimeout, cfg.MaxChainDepth, w)
			climbedCerts = append(climbedCerts, miniChain...)
			for _, info := range miniChain {
				if info == nil || info.Cert == nil || info.Cert.SerialNumber == nil {
					continue
				}
				serial := info.Cert.SerialNumber.String()
				already := false
				for _, existing := range pool {
					if existing != nil && existing.Cert != nil && existing.Cert.SerialNumber != nil &&
						existing.Cert.SerialNumber.String() == serial {
						already = true
						break
					}
				}
				if !already {
					pool = append(pool, info)
				}
			}
		}
		allCerts = append(climbedCerts, issuers...)
	}

	chain, err := cert.BuildChain(allCerts)
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to build certificate chain: %w", err)
	}

	nonceOpts := buildNonceOptions(cfg)

	// Auto-validate: fetch CRLs
	if cfg.AutoValidate && !cfg.NoAutoCRL {
		autoCRLs := crl.FetchForChain(chain, cfg.OCSPTimeout, w)
		crls = append(crls, autoCRLs...)
	}

	// Auto-validate: fetch OCSP
	if cfg.AutoValidate && !cfg.NoAutoOCSP {
		autoOCSPs, errs := ocsp.FetchForChain(chain, cfg.OCSPTimeout, nonceOpts)
		for _, err := range errs {
			_, _ = fmt.Fprintf(w, "Warning: auto OCSP fetch failed for %v\n", err)
		}
		if cfg.Verbosity >= 2 {
			for _, ocspInfo := range autoOCSPs {
				printOCSPResponseDebug(w, ocspInfo, nonceOpts)
			}
		}
		ocsps = append(ocsps, autoOCSPs...)
	}

	evalCtx := evaluator.Context{
		Policies:           policies,
		Registry:           reg,
		CRLs:               crls,
		OCSPs:              ocsps,
		Chain:              chain,
		ApplicationPurpose: cfg.ApplicationPurpose,
		CRLResolveTimeout:  crlResolveTimeout(cfg),
		CRLResolveMaxDepth: crlResolveMaxDepth(cfg),
		CRLResolveWarn:     w,
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
		cfg.OutputFmt = "text"
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
