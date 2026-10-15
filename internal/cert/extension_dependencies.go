package cert

import (
	"strconv"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

// BasicConstraintsDependenciesValid checks the dependencies of an encoded
// pathLenConstraint. Its path counting semantics are evaluated separately by
// PathLenConstraintValid.
func BasicConstraintsDependenciesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	facts, valid := basicConstraintsProfileFacts(certificate)
	if !valid {
		return false
	}
	if !facts.PathLenConstraintPresent {
		return true
	}
	if !facts.CA {
		return false
	}
	if !certificateExtension(certificate, oid.KeyUsage).Unique() ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	return true
}

// CanSignCertificates reports whether a certificate is an RFC 5280 CA and,
// when Key Usage is present, permits certificate signing. Strict extension
// decoding and duplicate detection are shared with the profile predicates.
func CanSignCertificates(certificate *x509.Certificate) bool {
	if certificate == nil || !IsCA(certificate) ||
		!BasicConstraintsDependenciesValid(certificate) {
		return false
	}
	keyUsage := certificateExtension(certificate, oid.KeyUsage)
	if !keyUsage.Present() {
		return true
	}
	return keyUsage.Unique() && KeyUsageDependenciesValid(certificate) &&
		certificate.KeyUsage&x509.KeyUsageCertSign != 0
}

// KeyUsageDependenciesValid enforces the profile dependency between Key Usage
// and Basic Constraints: keyCertSign requires a CA Basic Constraints
// assertion. RFC 5280 leaves the meaning of encipherOnly and decipherOnly
// undefined when keyAgreement is absent, but does not prohibit the encoding.
func KeyUsageDependenciesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	keyUsageExtension := certificateExtension(certificate, oid.KeyUsage)
	if !keyUsageExtension.Present() {
		return true
	}
	if !keyUsageExtension.Unique() {
		return false
	}

	keyUsage := certificate.KeyUsage
	if keyUsage&x509.KeyUsageCertSign != 0 {
		facts, valid := basicConstraintsProfileFacts(certificate)
		if !valid || !facts.CA {
			return false
		}
	}
	return true
}

// NameConstraintsDependenciesValid checks the profile requirement that Name
// Constraints appear only in CA certificates. Name matching itself remains a
// deliberately partial domain decision in NameConstraintsValid.
func NameConstraintsDependenciesValid(certificate *x509.Certificate) bool {
	return caOnlyExtensionValid(certificate, oid.NameConstraints)
}

// NameConstraintsDistancesValid checks the RFC 5280 profile restriction that
// every GeneralSubtree use the default minimum of zero and omit maximum.
func NameConstraintsDistancesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	match := certificateExtension(certificate, oid.NameConstraints)
	if !match.Present() {
		return true
	}
	extension, unique := match.Extension()
	if !unique {
		return false
	}

	facts, err := x509ext.DecodeNameConstraintsStrict(extension.Value)
	if err != nil {
		return false
	}
	subtrees := append(
		append([]x509ext.NameConstraintSubtreeFacts(nil), facts.PermittedSubtrees...),
		facts.ExcludedSubtrees...,
	)
	for _, subtree := range subtrees {
		if subtree.Minimum != 0 || subtree.MaximumPresent {
			return false
		}
	}
	return true
}

// CRLDistributionPointsDependenciesValid checks certificate-profile
// dependencies that do not require fetching or applying a CRL. Distribution
// point scope, CRL issuer resolution and reason masks are applied by the
// revocation processing in package crl.
func CRLDistributionPointsDependenciesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	match := certificateExtension(certificate, oid.CRLDistributionPoints)
	if !match.Present() {
		return true
	}
	extension, unique := match.Extension()
	if !unique {
		return false
	}

	facts, err := x509ext.DecodeCRLDistributionPointsStrict(extension.Value)
	if err != nil {
		return false
	}
	hasAllReasonsPoint := false
	for _, point := range facts.DistributionPoints {
		if !point.ReasonsPresent {
			hasAllReasonsPoint = true
		} else {
			if point.ReasonMask&^x509ext.AllReasons != 0 {
				return false
			}
			if point.ReasonMask == x509ext.AllReasons {
				hasAllReasonsPoint = true
			}
		}
		if len(point.CRLIssuerGeneralNameTags) > 0 &&
			(len(point.CRLIssuerGeneralNameTags) != 1 ||
				point.CRLIssuerGeneralNameTags[0] != 4) { // singular directoryName [4]
			return false
		}
	}
	return hasAllReasonsPoint
}

// PolicyMappingsDependenciesValid checks that Policy Mappings occurs only in
// CA certificates and that neither side of a mapping uses anyPolicy.
func PolicyMappingsDependenciesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	match := certificateExtension(certificate, oid.PolicyMappings)
	if !match.Present() {
		return true
	}
	extension, unique := match.Extension()
	if !unique {
		return false
	}
	basicConstraints, valid := basicConstraintsProfileFacts(certificate)
	if !valid || !basicConstraints.CA {
		return false
	}

	mappings, err := x509ext.DecodePolicyMappingsStrict(extension.Value)
	if err != nil {
		return false
	}
	for _, mapping := range mappings {
		if mapping.IssuerDomainPolicy == oid.AnyPolicy ||
			mapping.SubjectDomainPolicy == oid.AnyPolicy {
			return false
		}
	}
	return true
}

// PolicyMappingsIssuerPoliciesPresent checks the RFC 5280 recommendation that
// every issuerDomainPolicy also appears in this certificate's policies.
func PolicyMappingsIssuerPoliciesPresent(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	mappingsMatch := certificateExtension(certificate, oid.PolicyMappings)
	if !mappingsMatch.Present() {
		return true
	}
	mappingsExtension, unique := mappingsMatch.Extension()
	if !unique {
		return false
	}

	mappings, err := x509ext.DecodePolicyMappingsStrict(mappingsExtension.Value)
	if err != nil {
		return false
	}
	policiesMatch := certificateExtension(certificate, oid.CertificatePolicies)
	if !policiesMatch.Present() {
		return false
	}
	policiesExtension, unique := policiesMatch.Extension()
	if !unique {
		return false
	}
	policyIdentifiers, err := x509ext.DecodeCertificatePolicyIdentifiersStrict(policiesExtension.Value)
	if err != nil {
		return false
	}
	policies := make(map[string]struct{}, len(policyIdentifiers))
	for _, identifier := range policyIdentifiers {
		policies[identifier] = struct{}{}
	}
	for _, mapping := range mappings {
		if _, ok := policies[mapping.IssuerDomainPolicy]; !ok {
			return false
		}
	}
	return true
}

// PolicyConstraintsDependenciesValid checks the profile requirement that
// Policy Constraints appear only in CA certificates.
func PolicyConstraintsDependenciesValid(certificate *x509.Certificate) bool {
	return caOnlyExtensionValid(certificate, oid.PolicyConstraints)
}

// InhibitAnyPolicyDependenciesValid checks the profile requirement that
// inhibitAnyPolicy appear only in CA certificates.
func InhibitAnyPolicyDependenciesValid(certificate *x509.Certificate) bool {
	return caOnlyExtensionValid(certificate, oid.InhibitAnyPolicy)
}

func caOnlyExtensionValid(certificate *x509.Certificate, identifier string) bool {
	if certificate == nil {
		return false
	}
	match := certificateExtension(certificate, identifier)
	if !match.Present() {
		return true
	}
	if !match.Unique() {
		return false
	}
	basicConstraints, valid := basicConstraintsProfileFacts(certificate)
	return valid && basicConstraints.CA
}

func basicConstraintsProfileFacts(
	certificate *x509.Certificate,
) (x509ext.BasicConstraintsFacts, bool) {
	if certificate == nil {
		return x509ext.BasicConstraintsFacts{}, false
	}
	match := certificateExtension(certificate, oid.BasicConstraints)
	if match.Present() {
		extension, unique := match.Extension()
		if !unique {
			return x509ext.BasicConstraintsFacts{}, false
		}
		facts, err := x509ext.DecodeBasicConstraintsStrict(extension.Value)
		return facts, err == nil
	}

	// Preserve direct domain-test and adapter compatibility for callers that
	// supply typed x509 facts without the raw extension.
	present := certificate.MaxPathLen > 0 || certificate.MaxPathLenZero
	return x509ext.BasicConstraintsFacts{
		CA:                       certificate.BasicConstraintsValid && certificate.IsCA,
		PathLenConstraint:        certificate.MaxPathLen,
		PathLenConstraintDecimal: strconv.Itoa(certificate.MaxPathLen),
		PathLenConstraintFitsInt: true,
		PathLenConstraintPresent: present,
	}, true
}

func certificateExtension(certificate *x509.Certificate, identifier string) x509ext.ExtensionMatch {
	if certificate == nil {
		return x509ext.ExtensionMatch{}
	}
	return x509ext.NewExtensionIndex(certificate.Extensions).Lookup(identifier)
}
