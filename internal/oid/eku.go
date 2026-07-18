package oid

import "github.com/zmap/zcrypto/x509"

const (
	// Extended Key Usage identifiers from RFC 5280.
	ServerAuth      = "1.3.6.1.5.5.7.3.1"
	ClientAuth      = "1.3.6.1.5.5.7.3.2"
	CodeSigning     = "1.3.6.1.5.5.7.3.3"
	EmailProtection = "1.3.6.1.5.5.7.3.4"
	TimeStamping    = "1.3.6.1.5.5.7.3.8"
	OCSPSigning     = "1.3.6.1.5.5.7.3.9"
)

type extendedKeyUsage struct {
	usage x509.ExtKeyUsage
	oid   string
}

// extendedKeyUsages is the single source for policy names, zcrypto values,
// and dotted identifiers. ExtKeyUsageAny intentionally has no OID mapping
// here to preserve NormalizeOID's existing handling of the name "any".
var extendedKeyUsages = map[string]extendedKeyUsage{
	"any":             {usage: x509.ExtKeyUsageAny},
	"serverAuth":      {usage: x509.ExtKeyUsageServerAuth, oid: ServerAuth},
	"clientAuth":      {usage: x509.ExtKeyUsageClientAuth, oid: ClientAuth},
	"codeSigning":     {usage: x509.ExtKeyUsageCodeSigning, oid: CodeSigning},
	"emailProtection": {usage: x509.ExtKeyUsageEmailProtection, oid: EmailProtection},
	"timeStamping":    {usage: x509.ExtKeyUsageTimeStamping, oid: TimeStamping},
	"ocspSigning":     {usage: x509.ExtKeyUsageOcspSigning, oid: OCSPSigning},
}

// ExtKeyUsage returns the zcrypto usage value for a policy-facing EKU name.
func ExtKeyUsage(name string) (x509.ExtKeyUsage, bool) {
	descriptor, ok := extendedKeyUsages[name]
	return descriptor.usage, ok
}

// ExtKeyUsageOID returns the dotted identifier for a policy-facing EKU name.
func ExtKeyUsageOID(name string) (string, bool) {
	descriptor, ok := extendedKeyUsages[name]
	return descriptor.oid, ok && descriptor.oid != ""
}

// ExtKeyUsageToOID returns the OID string for a zcrypto ExtKeyUsage value.
func ExtKeyUsageToOID(usage x509.ExtKeyUsage) string {
	for _, descriptor := range extendedKeyUsages {
		if descriptor.usage == usage {
			return descriptor.oid
		}
	}
	return ""
}
