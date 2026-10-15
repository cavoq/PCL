// Package linter provides PCL lint runner orchestration.
package linter

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/output"
	pathpkg "github.com/cavoq/PCL/internal/path"
)

type Config struct {
	PolicyPaths []string // Multiple policy paths
	CertPath    string
	CertURLs    []string
	CertTimeout time.Duration
	CertSaveDir string
	IssuerPaths []string
	IssuerURLs  []string
	// TrustAnchorPaths are explicit, locally trusted certificate files or
	// directories used by RFC 5280 path validation. They are not inferred from
	// self-signed certificates in the issuer pool.
	TrustAnchorPaths []string
	CRLPath          string
	OCSPPath         string
	OCSPTimeout      time.Duration
	OutputFmt        string
	// ValidationTime fixes the evaluation time; zero means the current time.
	ValidationTime time.Time
	Verbosity      int
	ShowMeta       bool
	// ShowDetails adds human-readable rule explanations to text output.
	// Structured output always retains diagnostic fields.
	ShowDetails bool
	// Color marks text results with ANSI colors.
	Color bool
	// FailOn is the lowest severity of a failed rule that makes Run return
	// an error after writing the results: error, warning or info. Empty or
	// FailOnNone never fails the run.
	FailOn      string
	Diagnostics io.Writer // Optional warning/debug stream, separate from formatted results.

	// ApplicationPurpose is the explicit RFC 5280 extended-key-usage purpose
	// used while evaluating certificate profile semantics. It may be a stable
	// friendly name (for example, "serverAuth") or a dotted object identifier.
	ApplicationPurpose string

	// CertificatePolicyInputs are optional RFC 5280 Section 6.1.1 inputs.
	// Unconfigured inputs preserve certificatePolicyValid's operand-based
	// compatibility mode.
	CertificatePolicyInputs pathpkg.PolicyInputs

	// MaximumPathLength is the caller's initial maximum number of non-self-
	// issued intermediate certificates. The companion bit preserves an
	// explicit zero value.
	MaximumPathLength           int
	MaximumPathLengthConfigured bool
	// PathRevocation controls path revocation integration: none, if-present, or
	// required; unset means pathpkg.DefaultRevocationMode. It is used only
	// when explicit trust anchors enable validation.
	PathRevocation pathpkg.RevocationMode

	// Auto-validate mode options
	AutoValidate  bool // Enable automatic PKI resource fetching (OCSP, CRL, chain climbing)
	NoAutoChain   bool // Disable chain climbing via CA Issuers URLs
	NoAutoCRL     bool // Disable CRL fetching from CRL Distribution Points
	NoAutoOCSP    bool // Disable OCSP fetching for all certificates in chain
	MaxChainDepth int  // Maximum chain depth for climbing (default 10)

	// OCSP nonce options (RFC 9654)
	OCSPNonceLength int    // Length of nonce to generate (default 32, per RFC 9654)
	OCSPNonceValue  string // Custom nonce value in hex format (optional)
	NoOCSPNonce     bool   // Disable nonce in OCSP requests

	// OCSP request hash algorithm
	OCSPHashAlgorithm string // Hash algorithm for CertID: "sha1" (RFC 5019) or "sha256" (default, modern)
}

// Validate reports configurations that cannot produce lint results. Issuer
// certificates only support other inputs and are not linted on their own.
func (cfg Config) Validate() error {
	if len(cfg.PolicyPaths) == 0 {
		return errors.New("at least one policy path is required")
	}
	if _, ok := failOnRanks[cfg.FailOn]; !ok {
		return fmt.Errorf("unknown --fail-on severity %q: use error, warning, info or none", cfg.FailOn)
	}
	return cfg.validateInputs()
}

// validateInputs reports configurations without a certificate, CRL or OCSP
// input, and option values that would otherwise be ignored. Issuer
// certificates alone are not evaluated.
func (cfg Config) validateInputs() error {
	if cfg.CertificatePolicyInputs.IsConfigured() {
		for _, identifier := range cfg.CertificatePolicyInputs.InitialPolicySet {
			if !oid.ValidDotted(identifier) {
				return fmt.Errorf("initial policy set contains invalid object identifier %q", identifier)
			}
		}
	}
	if len(cfg.TrustAnchorPaths) > 0 && !cfg.hasCertificateInput() {
		return errors.New("--trust-anchor requires a certificate input")
	}
	if cfg.MaximumPathLengthConfigured && cfg.MaximumPathLength < 0 {
		return errors.New("--max-path-length must not be negative")
	}
	if cfg.MaximumPathLengthConfigured && len(cfg.TrustAnchorPaths) == 0 {
		return errors.New("--max-path-length requires --trust-anchor")
	}
	switch cfg.PathRevocation {
	case "", pathpkg.RevocationNone, pathpkg.RevocationIfPresent, pathpkg.RevocationRequired:
	default:
		return fmt.Errorf("unknown --path-revocation mode %q: use none, if-present or required", cfg.PathRevocation)
	}
	if !cfg.hasCertificateInput() && cfg.CRLPath == "" && cfg.OCSPPath == "" {
		return errors.New("no certificates, CRLs, or OCSP responses provided")
	}
	if err := output.CheckFormat(cfg.OutputFmt); err != nil {
		return err
	}
	return buildNonceOptions(cfg).Validate()
}

func (cfg Config) hasCertificateInput() bool {
	return cfg.CertPath != "" || len(cfg.CertURLs) > 0
}

func (cfg Config) hasIssuerInput() bool {
	return len(cfg.IssuerPaths) > 0 || len(cfg.IssuerURLs) > 0
}

// climbsCAIssuers reports whether certificates may be downloaded from CA
// Issuers URLs, to extend the chain or to find CRL and OCSP signers.
func (cfg Config) climbsCAIssuers() bool {
	return cfg.AutoValidate && !cfg.NoAutoChain
}
