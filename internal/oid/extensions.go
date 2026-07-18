package oid

const (
	// Certificate extension identifiers from RFC 5280.
	SubjectDirectoryAttributes = "2.5.29.9"
	SubjectKeyIdentifier       = "2.5.29.14"
	KeyUsage                   = "2.5.29.15"
	PrivateKeyUsagePeriod      = "2.5.29.16"
	SubjectAlternativeName     = "2.5.29.17"
	IssuerAlternativeName      = "2.5.29.18"
	BasicConstraints           = "2.5.29.19"
	NameConstraints            = "2.5.29.30"
	CRLDistributionPoints      = "2.5.29.31"
	CertificatePolicies        = "2.5.29.32"
	PolicyMappings             = "2.5.29.33"
	AuthorityKeyIdentifier     = "2.5.29.35"
	PolicyConstraints          = "2.5.29.36"
	ExtendedKeyUsage           = "2.5.29.37"
	FreshestCRL                = "2.5.29.46"
	InhibitAnyPolicy           = "2.5.29.54"
	AuthorityInfoAccess        = "1.3.6.1.5.5.7.1.1"
	SubjectInfoAccess          = "1.3.6.1.5.5.7.1.11"

	// CRL and CRL-entry extension identifiers from RFC 5280.
	CRLNumber                = "2.5.29.20"
	CRLReason                = "2.5.29.21"
	DeltaCRLIndicator        = "2.5.29.27"
	IssuingDistributionPoint = "2.5.29.28"
	CertificateIssuer        = "2.5.29.29"
)

// extensionNames contains the stable node aliases exposed by the certificate
// and CRL projections. It deliberately contains only extension identifiers;
// access-method identifiers have their own catalog in access.go.
var extensionNames = map[string]string{
	SubjectKeyIdentifier:     "subjectKeyIdentifier",
	KeyUsage:                 "keyUsage",
	SubjectAlternativeName:   "subjectAltName",
	IssuerAlternativeName:    "issuerAltName",
	BasicConstraints:         "basicConstraints",
	NameConstraints:          "nameConstraints",
	CRLDistributionPoints:    "cRLDistributionPoints",
	CertificatePolicies:      "certificatePolicies",
	AuthorityKeyIdentifier:   "authorityKeyIdentifier",
	ExtendedKeyUsage:         "extKeyUsage",
	AuthorityInfoAccess:      "authorityInfoAccess",
	SubjectInfoAccess:        "subjectInfoAccess",
	CRLReason:                "cRLReason",
	CRLNumber:                "cRLNumber",
	DeltaCRLIndicator:        "deltaCRLIndicator",
	IssuingDistributionPoint: "issuingDistributionPoint",
	CertificateIssuer:        "certificateIssuer",
}

// ExtensionName returns the stable node alias for an extension identifier.
func ExtensionName(identifier string) (string, bool) {
	name, ok := extensionNames[identifier]
	return name, ok
}
