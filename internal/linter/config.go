// Package linter provides PCL lint runner orchestration.
package linter

import (
	"errors"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/output"
)

type Config struct {
	PolicyPaths []string // Multiple policy paths
	CertPath    string
	CertURLs    []string
	CertTimeout time.Duration
	CertSaveDir string
	IssuerPath  string   // Single issuer path (backward compatible)
	IssuerPaths []string // Multiple issuer paths
	IssuerURLs  []string
	CRLPath     string
	OCSPPath    string
	OCSPTimeout time.Duration
	OutputFmt   string
	// ValidationTime fixes the evaluation time; zero means the current time.
	ValidationTime time.Time
	Verbosity      int
	ShowMeta       bool
	// Color marks text results with ANSI colors.
	Color       bool
	Diagnostics io.Writer // Optional warning/debug stream, separate from formatted results.

	// ApplicationPurpose is the explicit RFC 5280 extended-key-usage purpose
	// used while evaluating certificate profile semantics. It may be a stable
	// friendly name (for example, "serverAuth") or a dotted object identifier.
	ApplicationPurpose string

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
	return cfg.validateInputs()
}

// validateInputs reports configurations without a certificate, CRL or OCSP
// input, and option values that would otherwise be ignored. Issuer
// certificates alone are not evaluated.
func (cfg Config) validateInputs() error {
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
