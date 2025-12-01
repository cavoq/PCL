package main

import (
	"fmt"
	"os"

	"github.com/cavoq/RCV/internal/linter"
	"github.com/cavoq/RCV/internal/policy"
	"github.com/cavoq/RCV/internal/report"
	"github.com/cavoq/RCV/internal/utils"
	"github.com/spf13/cobra"
)

type InputOptions struct {
	PolicyPath string
	CertPath   string
	OutputFmt  string
}

func RunLinter(opts InputOptions) error {
	reporter := report.SelectReporter(opts.OutputFmt)

	policyFiles, err := utils.CollectPaths(opts.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to collect policy files: %w", err)
	}

	certFiles, err := utils.GetCertificates(opts.CertPath)
	if err != nil {
		return fmt.Errorf("failed to collect certificates: %w", err)
	}

	for _, polFile := range policyFiles {
		pol, err := policy.LoadPolicy(polFile)
		if err != nil {
			return fmt.Errorf("failed to load policy %s: %w", polFile, err)
		}

		for _, certFile := range certFiles {
			l := linter.NewLinter(certFile, pol)

			result, err := l.LintAll()
			if err != nil {
				return fmt.Errorf("lint failed for cert %v: %w", certFile, err)
			}

			output, err := reporter.Report(result)
			if err != nil {
				return fmt.Errorf("failed to format result for cert %v: %w", certFile, err)
			}

			fmt.Println(output)
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
