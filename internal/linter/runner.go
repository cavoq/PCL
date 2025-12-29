package linter

import (
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
)

func Run(cfg Config, w io.Writer) error {
	applyDefaults(&cfg)
	policies, err := policy.ParseDir(cfg.PolicyPath)
	if err != nil {
		policies = nil
		p, err := policy.ParseFile(cfg.PolicyPath)
		if err != nil {
			return fmt.Errorf("failed to parse policies: %w", err)
		}
		policies = append(policies, p)
	}

	certs, cleanup, err := loadCertificates(cfg)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}

	chain, err := cert.BuildChain(certs)
	if err != nil {
		return fmt.Errorf("failed to build chain: %w", err)
	}

	var ctxOpts []operator.ContextOption

	if cfg.CRLPath != "" {
		crls, err := crl.GetCRLs(cfg.CRLPath)
		if err != nil {
			return fmt.Errorf("failed to load CRLs: %w", err)
		}
		ctxOpts = append(ctxOpts, operator.WithCRLs(crls))
	}

	if cfg.OCSPPath != "" {
		ocsps, err := ocsp.GetOCSPs(cfg.OCSPPath)
		if err != nil {
			return fmt.Errorf("failed to load OCSP responses: %w", err)
		}
		ctxOpts = append(ctxOpts, operator.WithOCSPs(ocsps))
	}

	reg := operator.DefaultRegistry()

	var results []policy.Result

	for _, c := range chain {
		tree := zcrypto.BuildTree(c.Cert)
		ctx := operator.NewEvaluationContext(tree, c, chain, ctxOpts...)

		for _, p := range policies {
			res := policy.Evaluate(p, tree, reg, ctx)
			results = append(results, res)
		}
	}

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

func loadCertificates(cfg Config) ([]*cert.Info, func(), error) {
	var cleanup func()
	var certs []*cert.Info

	if cfg.CertPath != "" {
		loaded, err := cert.LoadCertificates(cfg.CertPath)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(cfg.CertURLs) > 0 {
		dir, tempCleanup, err := cert.DownloadCertificates(cfg.CertURLs, cfg.CertTimeout, cfg.CertSaveDir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download certificates: %w", err)
		}
		if tempCleanup != nil {
			cleanup = tempCleanup
		}
		loaded, err := cert.LoadCertificates(dir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load downloaded certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(certs) == 0 {
		return nil, cleanup, fmt.Errorf("no certificates provided")
	}

	return certs, cleanup, nil
}

func applyDefaults(cfg *Config) {
	if cfg.CertTimeout <= 0 {
		cfg.CertTimeout = 10 * time.Second
	}
	if cfg.OutputFmt == "" {
		cfg.OutputFmt = "text"
	}
}
