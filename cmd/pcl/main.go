package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cavoq/PCL/internal/data"
	"github.com/cavoq/PCL/internal/httpfetch"
	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
)

var version = "5.2.0"

func newRootCmd(opts *linter.Config) *cobra.Command {
	var dataOpts dataOptions
	root := &cobra.Command{
		Use:     "pcl",
		Short:   "Policy-driven PKI conformance engine",
		Version: version,
		// main reports errors once; usage is only shown for flag and argument
		// errors, which happen before PersistentPreRun.
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			cmd.SilenceUsage = true
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.Diagnostics = cmd.ErrOrStderr()
			opts.Color = colorOutput(cmd.OutOrStdout())
			if err := dataOpts.load(opts.Diagnostics); err != nil {
				return err
			}
			return linter.Run(*opts, cmd.OutOrStdout())
		},
	}

	root.Flags().StringSliceVar(&opts.PolicyPaths, "policy", nil, "Path to policy YAML file or directory (repeatable)")
	addInputFlags(root.Flags(), opts)
	root.Flags().StringVar(&opts.OutputFmt, "output", output.FormatText, "Output format: text, json, or yaml")
	root.Flags().CountVarP(&opts.Verbosity, "verbose", "v", "Increase output detail: -v shows passed, -vv includes skipped")
	root.Flags().BoolVar(&opts.ShowDetails, "details", false, "Show wrapped rule explanations in text output")
	root.Flags().BoolVar(&opts.ShowMeta, "show-meta", true, "Show lint meta information")
	root.Flags().StringVar(&opts.FailOn, "fail-on", linter.FailOnNone, "Exit with status 1 when a rule of this severity or higher fails: error, warning, info or none")

	addDataFlags(root.Flags(), &dataOpts)

	return root
}

// colorOutput reports whether text results written to w are colored: only
// for a terminal, and not when NO_COLOR is set (https://no-color.org).
func colorOutput(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// dataOptions select the external data, such as the Public Suffix List, that
// operators consult. Every command that evaluates policies loads it.
type dataOptions struct {
	PSLFile string
	UsePSL  bool
	DataDir string
}

func addDataFlags(flags *pflag.FlagSet, opts *dataOptions) {
	flags.StringVar(&opts.PSLFile, "psl-file", "", "Path to Public Suffix List file (default: ./data/public_suffix_list.dat or ~/.pcl/data/public_suffix_list.dat)")
	flags.BoolVar(&opts.UsePSL, "use-psl", true, "Enable PSL loading for TLD validation (BR 4.2.2, 3.2.2.6)")
	flags.StringVar(&opts.DataDir, "data-dir", "", "Directory for external data files (default: ./data or ~/.pcl/data)")
}

// load loads the selected data into the default loader. A --psl-file that
// cannot be loaded is an error. Without one, a missing list is not reported
// here: rules that use public suffix or TLD operators fail and say why. A
// list that exists but cannot be read is reported on w.
func (opts dataOptions) load(w io.Writer) error {
	data.DefaultLoader.SetDataDir(opts.DataDir)
	if opts.PSLFile == "" && !opts.UsePSL {
		return nil
	}
	err := data.DefaultLoader.LoadPSL(opts.PSLFile)
	switch {
	case err == nil:
		return nil
	case opts.PSLFile != "":
		return fmt.Errorf("--psl-file: %w", err)
	case errors.Is(err, data.ErrPSLNotFound):
		return nil
	default:
		_, err = fmt.Fprintf(w, "Warning: Public Suffix List not loaded: %v\n", err)
		return err
	}
}

// addInputFlags registers the flags that select and acquire certificates,
// CRLs and OCSP responses. Lint and inspect share them so both see the same
// inputs.
func addInputFlags(flags *pflag.FlagSet, opts *linter.Config) {
	flags.StringVar(&opts.CertPath, "cert", "", "Path to certificate file or directory (PEM/DER)")
	flags.StringSliceVar(&opts.CertURLs, "cert-url", nil, "Certificate URL (repeatable)")
	flags.DurationVar(&opts.CertTimeout, "cert-url-timeout", linter.DefaultCertTimeout, "Certificate URL timeout (e.g. 10s, 1m)")
	flags.StringVar(&opts.CertSaveDir, "cert-url-save-dir", "", "Directory to save downloaded certs (optional)")
	flags.StringSliceVar(&opts.IssuerPaths, "issuer", nil, "Path to issuer certificate file or directory (repeatable, PEM/DER)")
	flags.StringSliceVar(&opts.IssuerURLs, "issuer-url", nil, "Issuer certificate URL (repeatable)")
	flags.StringVar(&opts.CRLPath, "crl", "", "Path to CRL file or directory (PEM/DER)")
	flags.StringVar(&opts.OCSPPath, "ocsp", "", "Path to OCSP response file or directory (DER/PEM)")
	flags.DurationVar(&opts.OCSPTimeout, "ocsp-url-timeout", linter.DefaultOCSPTimeout, "OCSP request timeout (e.g. 5s, 10s)")
	flags.StringVar(&opts.ApplicationPurpose, "purpose", "", "Application purpose for RFC 5280 EKU evaluation (friendly name or OID)")

	// Auto-validate mode flags
	flags.BoolVar(&opts.AutoValidate, "auto-validate", false, "Enable automatic PKI resource fetching (OCSP, CRL, chain climbing)")
	flags.BoolVar(&opts.NoAutoChain, "no-auto-chain", false, "Disable chain climbing via CA Issuers URLs (only with --auto-validate)")
	flags.BoolVar(&opts.NoAutoCRL, "no-auto-crl", false, "Disable CRL fetching from CRL Distribution Points (only with --auto-validate)")
	flags.BoolVar(&opts.NoAutoOCSP, "no-auto-ocsp", false, "Disable OCSP fetching for all certificates in chain (only with --auto-validate)")
	flags.IntVar(&opts.MaxChainDepth, "max-chain-depth", linter.DefaultMaxChainDepth, "Maximum chain depth for climbing (only with --auto-validate)")

	// OCSP nonce options (RFC 9654)
	flags.IntVar(&opts.OCSPNonceLength, "ocsp-nonce-length", 32, "Nonce length in bytes for OCSP requests (default 32, per RFC 9654)")
	flags.StringVar(&opts.OCSPNonceValue, "ocsp-nonce-value", "", "Custom nonce value in hex format (e.g. 'aabbcc...')")
	flags.BoolVar(&opts.NoOCSPNonce, "no-ocsp-nonce", false, "Disable nonce in OCSP requests")

	// OCSP request hash algorithm (RFC 5019 vs modern)
	flags.StringVar(&opts.OCSPHashAlgorithm, "ocsp-hash", "sha256", "Hash algorithm for OCSP CertID: 'sha1' (RFC 5019) or 'sha256' (default, modern)")
}

func newInspectCmd() *cobra.Command {
	var opts linter.Config
	var inspect linter.InspectOptions
	var dataOpts dataOptions

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Print the node tree that policies evaluate",
		Long: `Print the node tree that policies evaluate for each certificate, CRL and
OCSP response, after the same loading, chain building and automatic retrieval
as a lint run. Every path shown can be used as a rule target.`,
		Example: `  pcl inspect --cert leaf.pem --issuer chain/
  pcl inspect --cert leaf.pem --paths | grep subjectAltName
  pcl inspect --crl list.crl --output json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.Diagnostics = cmd.ErrOrStderr()
			if err := dataOpts.load(opts.Diagnostics); err != nil {
				return err
			}
			return linter.Inspect(opts, inspect, cmd.OutOrStdout())
		},
	}

	addInputFlags(cmd.Flags(), &opts)
	addDataFlags(cmd.Flags(), &dataOpts)
	cmd.Flags().StringVar(&opts.OutputFmt, "output", output.FormatText, "Output format: text, json, or yaml")
	cmd.Flags().BoolVar(&inspect.Paths, "paths", false, "List every rule target path with its value type and value instead of the tree")
	return cmd
}

func newSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of policy files",
		Long: `Print the JSON Schema (draft-07) of policy files for editor completion and
validation. Reference the published copy from a policy with:

  # yaml-language-server: $schema=` + policy.SchemaID,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			schema, err := policy.JSONSchema(operator.DefaultRegistry())
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(schema)
			return err
		},
	}
}

func newTestCmd() *cobra.Command {
	var dataOpts dataOptions
	cmd := &cobra.Command{
		Use:   "test <file-or-directory>...",
		Short: "Run policy test suites",
		Long: `Run policy test suites: YAML files that lint example inputs with a policy
and state the expected verdicts per input and rule. Directories are searched
for *` + linter.PolicyTestSuffix + ` files. Paths inside a suite are relative to the suite file.`,
		Example: `  pcl test policies/tests
  pcl test my-profile.test.yaml`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := dataOpts.load(cmd.ErrOrStderr()); err != nil {
				return err
			}
			summary, err := linter.RunPolicyTests(args, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if summary.Failed > 0 {
				return fmt.Errorf("%d policy test(s) failed", summary.Failed)
			}
			return nil
		},
	}
	addDataFlags(cmd.Flags(), &dataOpts)
	return cmd
}

func newUpdateDataCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "update-data",
		Short: "Download and update external data files (PSL)",
		RunE: func(*cobra.Command, []string) error {
			return data.UpdateData(dataDir)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Directory to store data files (default: ./data or ~/.pcl/data)")

	return cmd
}

func main() {
	httpfetch.UserAgent = "pcl/" + version
	var opts linter.Config

	root := newRootCmd(&opts)
	root.AddCommand(newInspectCmd())
	root.AddCommand(newSchemaCmd())
	root.AddCommand(newTestCmd())
	root.AddCommand(newUpdateDataCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
