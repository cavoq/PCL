package main

import (
	"fmt"
	"os"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/report"
	"github.com/cavoq/PCL/internal/utils"
	"github.com/spf13/cobra"
)

type InputOptions struct {
	PolicyPath string
	CertPath   string
	OutputFmt  string
}

func RunLinter(opts InputOptions) error {
	certs, err := utils.GetCertificates(opts.CertPath)
	if err != nil {
		return fmt.Errorf("failed to collect certificates: %w", err)
	}

	policyChain, err := policy.GetPolicyChain(opts.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to load policy chain: %w", err)
	}

	l := &linter.Linter{}
	l.CreateJobs(certs, policyChain, opts.CertPath, opts.PolicyPath)
	l.Execute()

	reporter := report.SelectReporter(opts.OutputFmt)
	if err := report.ReportLintRun(reporter, l.Run); err != nil {
		return err
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
