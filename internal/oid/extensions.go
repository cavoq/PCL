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
	HoldInstructionCode      = "2.5.29.23"
	InvalidityDate           = "2.5.29.24"
	DeltaCRLIndicator        = "2.5.29.27"
	IssuingDistributionPoint = "2.5.29.28"
	CertificateIssuer        = "2.5.29.29"
)

// ExtensionLocation identifies the signed-object structure in which an
// extension is defined. It is identity metadata, not a claim that PCL fully
// processes the extension's value.
type ExtensionLocation uint8

const (
	ExtensionInCertificate ExtensionLocation = 1 << iota
	ExtensionInCRL
	ExtensionInCRLEntry
)

type extensionDefinition struct {
	identifier string
	name       string
	locations  ExtensionLocation
}

// extensionCatalog is the single source of truth for RFC 5280 extension
// identifiers, stable tree aliases, and their signed-object locations.
// Format adapters remain responsible for decoding extension values.
var extensionCatalog = []extensionDefinition{
	{SubjectDirectoryAttributes, "subjectDirectoryAttributes", ExtensionInCertificate},
	{SubjectKeyIdentifier, "subjectKeyIdentifier", ExtensionInCertificate},
	{KeyUsage, "keyUsage", ExtensionInCertificate},
	{PrivateKeyUsagePeriod, "privateKeyUsagePeriod", ExtensionInCertificate},
	{SubjectAlternativeName, "subjectAltName", ExtensionInCertificate},
	{IssuerAlternativeName, "issuerAltName", ExtensionInCertificate | ExtensionInCRL},
	{BasicConstraints, "basicConstraints", ExtensionInCertificate},
	{CRLNumber, "cRLNumber", ExtensionInCRL},
	{CRLReason, "cRLReason", ExtensionInCRLEntry},
	{HoldInstructionCode, "holdInstructionCode", ExtensionInCRLEntry},
	{InvalidityDate, "invalidityDate", ExtensionInCRLEntry},
	{DeltaCRLIndicator, "deltaCRLIndicator", ExtensionInCRL},
	{IssuingDistributionPoint, "issuingDistributionPoint", ExtensionInCRL},
	{CertificateIssuer, "certificateIssuer", ExtensionInCRLEntry},
	{NameConstraints, "nameConstraints", ExtensionInCertificate},
	{CRLDistributionPoints, "cRLDistributionPoints", ExtensionInCertificate},
	{CertificatePolicies, "certificatePolicies", ExtensionInCertificate},
	{PolicyMappings, "policyMappings", ExtensionInCertificate},
	{AuthorityKeyIdentifier, "authorityKeyIdentifier", ExtensionInCertificate | ExtensionInCRL},
	{PolicyConstraints, "policyConstraints", ExtensionInCertificate},
	{ExtendedKeyUsage, "extKeyUsage", ExtensionInCertificate},
	{FreshestCRL, "freshestCRL", ExtensionInCertificate | ExtensionInCRL},
	{InhibitAnyPolicy, "inhibitAnyPolicy", ExtensionInCertificate},
	{AuthorityInfoAccess, "authorityInfoAccess", ExtensionInCertificate | ExtensionInCRL},
	{SubjectInfoAccess, "subjectInfoAccess", ExtensionInCertificate},
}

var (
	extensionByIdentifier, extensionByName = indexExtensions(extensionCatalog)
)

func indexExtensions(definitions []extensionDefinition) (map[string]extensionDefinition, map[string]string) {
	byIdentifier := make(map[string]extensionDefinition, len(definitions))
	byName := make(map[string]string, len(definitions))
	for _, definition := range definitions {
		byIdentifier[definition.identifier] = definition
		byName[definition.name] = definition.identifier
	}
	return byIdentifier, byName
}

// ExtensionName returns the stable node alias for an extension identifier.
func ExtensionName(identifier string) (string, bool) {
	definition, ok := extensionByIdentifier[identifier]
	return definition.name, ok
}

// ExtensionOID resolves a stable extension alias to its identifier.
func ExtensionOID(name string) (string, bool) {
	identifier, ok := extensionByName[name]
	return identifier, ok
}

// ExtensionKnownAt reports whether RFC 5280 defines identifier at location.
// This must not be used as proof that PCL has implemented the extension's
// semantic processing.
func ExtensionKnownAt(identifier string, location ExtensionLocation) bool {
	definition, ok := extensionByIdentifier[identifier]
	return ok && definition.locations&location != 0
}
