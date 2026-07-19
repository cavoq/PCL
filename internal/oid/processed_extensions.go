package oid

// processedExtensionDefinition records extension support implemented by PCL.
// It is deliberately separate from extensionCatalog: knowing an RFC-defined
// identifier and its legal location is not evidence that PCL processes its
// value there.
type processedExtensionDefinition struct {
	identifier string
	location   ExtensionLocation
}

// processedExtensionRegistry is intentionally conservative. An entry means
// that the current profile implementation parses and projects enough of the
// extension to evaluate its supported profile behavior at that exact location.
// It does not claim that future Section 6 path effects are implemented.
var processedExtensionRegistry = []processedExtensionDefinition{
	// Certificate extensions with strict profile-facing parsing/projection and
	// an explicit malformed marker. CRL and CRL-entry extensions remain absent
	// until P3 owns their critical-extension processing.
	{KeyUsage, ExtensionInCertificate},
	{SubjectAlternativeName, ExtensionInCertificate},
	{IssuerAlternativeName, ExtensionInCertificate},
	{BasicConstraints, ExtensionInCertificate},
	{NameConstraints, ExtensionInCertificate},
	{CRLDistributionPoints, ExtensionInCertificate},
	{CertificatePolicies, ExtensionInCertificate},
	{PolicyMappings, ExtensionInCertificate},
	{PolicyConstraints, ExtensionInCertificate},
	{ExtendedKeyUsage, ExtensionInCertificate},
	{InhibitAnyPolicy, ExtensionInCertificate},
	{AuthorityInfoAccess, ExtensionInCertificate},
}

var processedExtensionsByLocation = indexProcessedExtensions(processedExtensionRegistry)

func indexProcessedExtensions(
	definitions []processedExtensionDefinition,
) map[ExtensionLocation]map[string]struct{} {
	byLocation := make(map[ExtensionLocation]map[string]struct{})
	for _, definition := range definitions {
		identifiers := byLocation[definition.location]
		if identifiers == nil {
			identifiers = make(map[string]struct{})
			byLocation[definition.location] = identifiers
		}
		identifiers[definition.identifier] = struct{}{}
	}
	return byLocation
}

// ExtensionProcessableAt reports whether PCL explicitly processes identifier
// at the exact signed-object location. Combined or unknown locations return
// false so callers cannot accidentally broaden support with a bit mask.
func ExtensionProcessableAt(identifier string, location ExtensionLocation) bool {
	identifiers, ok := processedExtensionsByLocation[location]
	if !ok {
		return false
	}
	_, ok = identifiers[identifier]
	return ok
}
