package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/spf13/cobra"
)

type InputOptions struct {
	PolicyPath string
	CertPath   string
	OutputFmt  string
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

	reg := operator.DefaultRegistry()

	var results []policy.Result

	for _, c := range chain {
		tree := zcrypto.BuildTree(c.Cert)
		ctx := operator.NewEvaluationContext(tree, c, chain)

		for _, p := range policies {
			res := policy.Evaluate(p, tree, reg, ctx)
			results = append(results, res)
		}
	}

	return outputResults(results, opts.OutputFmt)
}

func outputResults(results []policy.Result, format string) error {
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	for _, res := range results {
		fmt.Printf("Policy: %s | Cert: %s | Verdict: %s\n", res.PolicyID, res.CertType, res.Verdict)
		for _, r := range res.Results {
			status := "PASS"
			if r.Skipped {
				status = "SKIP"
			} else if !r.Passed {
				status = "FAIL"
			}
			fmt.Printf("  [%s] %s\n", status, r.RuleID)
		}
	}
	return nil
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
	root.Flags().StringVar(&opts.OutputFmt, "output", "text", "Output format: text or json")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
