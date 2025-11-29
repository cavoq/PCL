package main

import (
	"fmt"
	"os"

	"github.com/cavoq/RCV/internal/linter"
	"github.com/cavoq/RCV/internal/policy"
	"github.com/cavoq/RCV/internal/report"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "rcvlint",
		Short: "Policy-based X.509 certificate linter",
		RunE: func(cmd *cobra.Command, args []string) error {
			policyPath, _ := cmd.Flags().GetString("policy")
			certPath, _ := cmd.Flags().GetString("cert")

			if policyPath == "" || certPath == "" {
				return fmt.Errorf("--policy and --cert are required")
			}

			pol, err := policy.LoadPolicy(policyPath)
			if err != nil {
				return fmt.Errorf("failed to load policy: %w", err)
			}

			l, err := linter.FromCert(certPath, pol)
			if err != nil {
				return fmt.Errorf("failed to create linter: %w", err)
			}

			r, err := l.LintAll()
			if err != nil {
				return fmt.Errorf("lint failed: %w", err)
			}

			var rr = report.FormatResult(r)
			fmt.Println(rr)
			return nil
		},
	}

	root.Flags().String("policy", "", "Path to policy YAML file")
	root.Flags().String("cert", "", "Path to certificate file (PEM/DER)")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
