package linter

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
)

func Run(cfg Config, w io.Writer) error {
	applyDefaults(&cfg)

	// Load policies
	policies, err := loadPolicies(cfg.PolicyPaths)
	if err != nil {
		return err
	}

	reg := operator.DefaultRegistry()
	var results []policy.Result
	var cleanup func()

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
	if err != nil {
		return err
	}
	if issuerCleanup != nil {
		cleanup = issuerCleanup
	}

	if hasCert {
		results, cleanup = processCertificates(cfg, policies, reg, crls, ocsps, issuers, cleanup, w)
	} else if len(crls) > 0 {
		results = evaluateCRLOnly(policies, reg, crls, issuers)
	} else if len(ocsps) > 0 {
		results = evaluateOCSPOnly(policies, reg, ocsps)
	} else {
		return fmt.Errorf("no certificates, CRLs, or OCSP responses provided")
	}

	// Run cleanup at the end
	if cleanup != nil {
		cleanup()
	}

	// Output results
	return outputResults(cfg, results, w)
}

func loadPolicies(paths []string) ([]policy.Policy, error) {
	var policies []policy.Policy
	for _, path := range paths {
		isDir, err := isDirectory(path)
		if err != nil {
			return nil, fmt.Errorf("checking policy path %s: %w", path, err)
		}

		if isDir {
			p, err := policy.ParseDir(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse policy directory %s: %w", path, err)
			}
			policies = append(policies, p...)
		} else {
			p, err := policy.ParseFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse policy file %s: %w", path, err)
			}
			policies = append(policies, p)
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
	return loadIssuers(cfg, nil)
}

func processCertificates(cfg Config, policies []policy.Policy, reg *operator.Registry, crls []*crl.Info, ocsps []*ocsp.Info, issuers []*cert.Info, existingCleanup func(), w io.Writer) ([]policy.Result, func()) {
	// Load leaf certificates
	var cleanup func() //nolint:prealloc // overwritten by loadCertificates
	certs, certCleanup, err := loadCertificates(cfg)
	if err != nil {
		return nil, existingCleanup
	}

	// Combine cleanup functions
	if certCleanup != nil {
		prevCleanup := existingCleanup
		cleanup = func() {
			certCleanup()
			if prevCleanup != nil {
				prevCleanup()
			}
		}
	} else {
		cleanup = existingCleanup
	}

	// Build chain
	allCerts := append(certs, issuers...)
	if len(allCerts) == 0 {
		return nil, cleanup
	}

	// Auto-validate: climb chain via CA Issuers URLs
	if cfg.AutoValidate && !cfg.NoAutoChain {
		var climbedCerts []*cert.Info
		for _, c := range certs {
			if c.Cert == nil {
				continue
			}
			miniChain := []*cert.Info{c}
			miniChain = cert.ClimbChain(miniChain, cfg.CertTimeout, cfg.MaxChainDepth, w)
			climbedCerts = append(climbedCerts, miniChain...)
		}
		allCerts = append(climbedCerts, issuers...)
	}

	chain, err := cert.BuildChain(allCerts)
	if err != nil {
		_, _ = fmt.Fprintf(w, "Warning: failed to build chain: %v\n", err)
		return nil, cleanup
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

	// Evaluate certificates
	evalCtx := EvaluationContext{
		Policies: policies,
		Registry: reg,
		CRLs:     crls,
		OCSPs:    ocsps,
		Chain:    chain,
	}
	results := evaluateChain(evalCtx)

	// Evaluate OCSP if present
	if len(ocsps) > 0 {
		results = append(results, evaluateOCSP(evalCtx)...)
	}

	// Evaluate CRLs if present (dual evaluation)
	if len(crls) > 0 {
		results = append(results, evaluateCRL(evalCtx)...)
	}

	return results, cleanup
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

func applyDefaults(cfg *Config) {
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
