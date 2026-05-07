package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cavoq/PCL/internal/data"
	"github.com/cavoq/PCL/internal/linter"
)

func newRootCmd(opts *linter.Config) *cobra.Command {
	root := &cobra.Command{
		Use:   "pcl",
		Short: "Policy-based X.509 certificate linter",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Load PSL if specified or if file exists in default location
			if opts.PSLFile != "" || opts.UsePSL {
				if err := data.DefaultLoader.LoadPSL(opts.PSLFile); err != nil {
					// If PSL loading fails, continue with regex fallback
					fmt.Fprintf(os.Stderr, "Warning: PSL not loaded (%v), using regex fallback\n", err)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(opts.PolicyPaths) == 0 {
				return fmt.Errorf("--policy is required")
			}
			hasCert := opts.CertPath != "" || len(opts.CertURLs) > 0
			hasIssuer := len(opts.IssuerPaths) > 0 || len(opts.IssuerURLs) > 0
			if !hasCert && !hasIssuer && opts.CRLPath == "" && opts.OCSPPath == "" {
				return fmt.Errorf("at least one of --cert, --cert-url, --issuer, --issuer-url, --crl, or --ocsp is required")
			}
			return linter.Run(*opts, cmd.OutOrStdout())
		},
	}

	root.Flags().StringSliceVar(&opts.PolicyPaths, "policy", nil, "Path to policy YAML file or directory (repeatable)")
	root.Flags().StringVar(&opts.CertPath, "cert", "", "Path to certificate file or directory (PEM/DER)")
	root.Flags().StringSliceVar(&opts.CertURLs, "cert-url", nil, "Certificate URL (repeatable)")
	root.Flags().DurationVar(&opts.CertTimeout, "cert-url-timeout", 10*time.Second, "Certificate URL timeout (e.g. 10s, 1m)")
	root.Flags().StringVar(&opts.CertSaveDir, "cert-url-save-dir", "", "Directory to save downloaded certs (optional)")
	root.Flags().StringSliceVar(&opts.IssuerPaths, "issuer", nil, "Path to issuer certificate file or directory (repeatable, PEM/DER)")
	root.Flags().StringSliceVar(&opts.IssuerURLs, "issuer-url", nil, "Issuer certificate URL (repeatable)")
	root.Flags().StringVar(&opts.CRLPath, "crl", "", "Path to CRL file or directory (PEM/DER)")
	root.Flags().StringVar(&opts.OCSPPath, "ocsp", "", "Path to OCSP response file or directory (DER/PEM)")
	root.Flags().DurationVar(&opts.OCSPTimeout, "ocsp-url-timeout", 5*time.Second, "OCSP request timeout (e.g. 5s, 10s)")
	root.Flags().StringVar(&opts.OutputFmt, "output", "text", "Output format: text, json, or yaml")
	root.Flags().CountVarP(&opts.Verbosity, "verbose", "v", "Increase output detail: -v shows passed, -vv includes skipped")
	root.Flags().BoolVar(&opts.ShowMeta, "show-meta", true, "Show lint meta information")

	// Auto-validate mode flags
	root.Flags().BoolVar(&opts.AutoValidate, "auto-validate", false, "Enable automatic PKI resource fetching (OCSP, CRL, chain climbing)")
	root.Flags().BoolVar(&opts.NoAutoChain, "no-auto-chain", false, "Disable chain climbing via CA Issuers URLs (only with --auto-validate)")
	root.Flags().BoolVar(&opts.NoAutoCRL, "no-auto-crl", false, "Disable CRL fetching from CRL Distribution Points (only with --auto-validate)")
	root.Flags().BoolVar(&opts.NoAutoOCSP, "no-auto-ocsp", false, "Disable OCSP fetching for all certificates in chain (only with --auto-validate)")
	root.Flags().IntVar(&opts.MaxChainDepth, "max-chain-depth", 10, "Maximum chain depth for climbing (only with --auto-validate)")

	// OCSP nonce options (RFC 9654)
	root.Flags().IntVar(&opts.OCSPNonceLength, "ocsp-nonce-length", 32, "Nonce length in bytes for OCSP requests (default 32, per RFC 9654)")
	root.Flags().StringVar(&opts.OCSPNonceValue, "ocsp-nonce-value", "", "Custom nonce value in hex format (e.g. 'aabbcc...')")
	root.Flags().BoolVar(&opts.NoOCSPNonce, "no-ocsp-nonce", false, "Disable nonce in OCSP requests")

	// OCSP request hash algorithm (RFC 5019 vs modern)
	root.Flags().StringVar(&opts.OCSPHashAlgorithm, "ocsp-hash", "sha256", "Hash algorithm for OCSP CertID: 'sha1' (RFC 5019) or 'sha256' (default, modern)")

	// PSL/TLD data options
	root.Flags().StringVar(&opts.PSLFile, "psl-file", "", "Path to Public Suffix List file (default: ./data/public_suffix_list.dat or ~/.pcl/data/public_suffix_list.dat)")
	root.Flags().BoolVar(&opts.UsePSL, "use-psl", true, "Enable PSL loading for TLD validation (BR 4.2.2, 3.2.2.6)")
	root.Flags().StringVar(&opts.DataDir, "data-dir", "", "Directory for external data files (default: ./data or ~/.pcl/data)")

	return root
}

func newUpdateDataCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "update-data",
		Short: "Download and update external data files (PSL)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return data.UpdateData(dataDir)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Directory to store data files (default: ./data or ~/.pcl/data)")

	return cmd
}

func main() {
	var opts linter.Config

	root := newRootCmd(&opts)
	root.AddCommand(newUpdateDataCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}