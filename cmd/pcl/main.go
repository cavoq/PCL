package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cavoq/PCL/internal/linter"
)

func newRootCmd(opts *linter.Config) *cobra.Command {
	root := &cobra.Command{
		Use:   "PCL",
		Short: "Policy-based X.509 certificate linter",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.PolicyPath == "" {
				return fmt.Errorf("--policy is required")
			}
			if opts.CertPath == "" && len(opts.CertURLs) == 0 {
				return fmt.Errorf("--cert or --cert-url is required")
			}
			return linter.Run(*opts, cmd.OutOrStdout())
		},
	}

	root.Flags().StringVar(&opts.PolicyPath, "policy", "", "Path to policy YAML file or directory")
	root.Flags().StringVar(&opts.CertPath, "cert", "", "Path to certificate file or directory (PEM/DER)")
	root.Flags().StringSliceVar(&opts.CertURLs, "cert-url", nil, "Certificate URL (repeatable)")
	root.Flags().DurationVar(&opts.CertTimeout, "cert-url-timeout", 10*time.Second, "Certificate URL timeout (e.g. 10s, 1m)")
	root.Flags().StringVar(&opts.CertSaveDir, "cert-url-save-dir", "", "Directory to save downloaded certs (optional)")
	root.Flags().StringVar(&opts.CRLPath, "crl", "", "Path to CRL file or directory (PEM/DER)")
	root.Flags().StringVar(&opts.OCSPPath, "ocsp", "", "Path to OCSP response file or directory (DER/PEM)")
	root.Flags().StringVar(&opts.OutputFmt, "output", "text", "Output format: text, json, or yaml")
	root.Flags().CountVarP(&opts.Verbosity, "verbose", "v", "Increase output detail: -v shows passed, -vv includes skipped")
	root.Flags().BoolVar(&opts.ShowMeta, "show-meta", true, "Show lint meta information")

	return root
}

func main() {
	var opts linter.Config

	if err := newRootCmd(&opts).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
