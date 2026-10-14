// Package linter provides PCL lint runner orchestration.
package linter

import (
	"errors"
	"io"
	"time"
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
	Verbosity   int
	ShowMeta    bool
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

	// PSL/TLD data options
	PSLFile string // Path to Public Suffix List file (optional)
	UsePSL  bool   // Enable PSL loading (default: true if file exists)
	DataDir string // Directory for external data files (optional)
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
// input. Issuer certificates alone are not evaluated.
func (cfg Config) validateInputs() error {
	if !cfg.hasCertificateInput() && cfg.CRLPath == "" && cfg.OCSPPath == "" {
		return errors.New("no certificates, CRLs, or OCSP responses provided")
	}
	return nil
}

func (cfg Config) hasCertificateInput() bool {
	return cfg.CertPath != "" || len(cfg.CertURLs) > 0
}

func (cfg Config) hasIssuerInput() bool {
	return len(cfg.IssuerPaths) > 0 || len(cfg.IssuerURLs) > 0
}
