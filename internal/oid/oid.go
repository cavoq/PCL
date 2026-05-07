package oid

import "github.com/zmap/zcrypto/x509"

const (
	// Extended Key Usage OIDs (RFC 5280)
	ServerAuth      = "1.3.6.1.5.5.7.3.1"
	ClientAuth      = "1.3.6.1.5.5.7.3.2"
	CodeSigning     = "1.3.6.1.5.5.7.3.3"
	EmailProtection = "1.3.6.1.5.5.7.3.4"
	TimeStamping    = "1.3.6.1.5.5.7.3.8"
	OCSPSigning     = "1.3.6.1.5.5.7.3.9"

	// CRL Extension OIDs (RFC 5280)
	DeltaCRLIndicator        = "2.5.29.27"
	IssuingDistributionPoint = "2.5.29.29"
)

// NormalizeOID converts a friendly name to its OID string.
// If the input is already an OID or a built-in cert type, it is returned unchanged.
func NormalizeOID(nameOrOID string) string {
	switch nameOrOID {
	case "serverAuth":
		return ServerAuth
	case "clientAuth":
		return ClientAuth
	case "codeSigning":
		return CodeSigning
	case "emailProtection":
		return EmailProtection
	case "timeStamping":
		return TimeStamping
	case "ocspSigning":
		return OCSPSigning
	case "deltaCRLIndicator":
		return DeltaCRLIndicator
	case "issuingDistributionPoint":
		return IssuingDistributionPoint
	default:
		return nameOrOID
	}
}

// ExtKeyUsageToOID returns the OID string for an x509.ExtKeyUsage value.
func ExtKeyUsageToOID(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return ServerAuth
	case x509.ExtKeyUsageClientAuth:
		return ClientAuth
	case x509.ExtKeyUsageCodeSigning:
		return CodeSigning
	case x509.ExtKeyUsageEmailProtection:
		return EmailProtection
	case x509.ExtKeyUsageTimeStamping:
		return TimeStamping
	case x509.ExtKeyUsageOcspSigning:
		return OCSPSigning
	default:
		return ""
	}
}
