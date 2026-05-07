package linter

import "time"

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
