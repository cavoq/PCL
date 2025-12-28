package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
)

type InputOptions struct {
	PolicyPath  string
	CertPath    string
	CRLPath     string
	OCSPPath    string
	OutputFmt   string
	ShowPassed  bool
	ShowFailed  bool
	ShowSkipped bool
	ShowMeta    bool
}

func RunLinter(opts InputOptions) error {
	policies, err := policy.ParseDir(opts.PolicyPath)
	if err != nil {
		policies = nil
		p, err := policy.ParseFile(opts.PolicyPath)
		if err != nil {
			return fmt.Errorf("failed to parse policies: %w", err)
		}
		policies = append(policies, p)
	}

	certs, err := cert.GetCertificates(opts.CertPath)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	chain, err := cert.BuildChain(certs)
	if err != nil {
		return fmt.Errorf("failed to build chain: %w", err)
	}

	var ctxOpts []operator.ContextOption

	if opts.CRLPath != "" {
		crls, err := crl.GetCRLs(opts.CRLPath)
		if err != nil {
			return fmt.Errorf("failed to load CRLs: %w", err)
		}
		ctxOpts = append(ctxOpts, operator.WithCRLs(crls))
	}

	if opts.OCSPPath != "" {
		ocsps, err := ocsp.GetOCSPs(opts.OCSPPath)
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
		ShowPassed:  opts.ShowPassed,
		ShowFailed:  opts.ShowFailed,
		ShowSkipped: opts.ShowSkipped,
		ShowMeta:    opts.ShowMeta,
	}

	lintOutput := output.FromPolicyResults(results)
	lintOutput = output.FilterRules(lintOutput, outputOpts)

	formatter := output.GetFormatter(opts.OutputFmt, outputOpts)
	return formatter.Format(os.Stdout, lintOutput)
}

func main() {
	var opts InputOptions

	root := &cobra.Command{
		Use:   "PCL",
		Short: "Policy-based X.509 certificate linter",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.PolicyPath == "" || opts.CertPath == "" {
				return fmt.Errorf("--policy and --cert are required")
			}
			return RunLinter(opts)
		},
	}

	root.Flags().StringVar(&opts.PolicyPath, "policy", "", "Path to policy YAML file or directory")
	root.Flags().StringVar(&opts.CertPath, "cert", "", "Path to certificate file or directory (PEM/DER)")
	root.Flags().StringVar(&opts.CRLPath, "crl", "", "Path to CRL file or directory (PEM/DER)")
	root.Flags().StringVar(&opts.OCSPPath, "ocsp", "", "Path to OCSP response file or directory (DER/PEM)")
	root.Flags().StringVar(&opts.OutputFmt, "output", "text", "Output format: text, json, or yaml")
	root.Flags().BoolVar(&opts.ShowPassed, "show-passed", true, "Show passed rules")
	root.Flags().BoolVar(&opts.ShowFailed, "show-failed", true, "Show failed rules")
	root.Flags().BoolVar(&opts.ShowSkipped, "show-skipped", true, "Show skipped rules")
	root.Flags().BoolVar(&opts.ShowMeta, "show-meta", true, "Show lint meta information")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
