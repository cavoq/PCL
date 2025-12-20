package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type InputOptions struct {
	PolicyPath string
	CertPath   string
	OutputFmt  string
}

func RunLinter(opts InputOptions) error {
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
