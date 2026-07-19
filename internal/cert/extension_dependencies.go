package cert

import (
	"strconv"

	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/oid"
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
	if !certificateHasExtension(certificate, oid.KeyUsage) ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	return true
}

// KeyUsageDependenciesValid enforces the profile dependency between Key Usage
// and Basic Constraints: keyCertSign requires a CA Basic Constraints
// assertion. RFC 5280 leaves the meaning of encipherOnly and decipherOnly
// undefined when keyAgreement is absent, but does not prohibit the encoding.
func KeyUsageDependenciesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	if !certificateHasExtension(certificate, oid.KeyUsage) {
		return true
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
	value, present := certificateExtensionValue(certificate, oid.NameConstraints)
	if !present {
		return true
	}

	facts, err := certzcrypto.DecodeNameConstraintsStrict(value)
	if err != nil {
		return false
	}
	subtrees := append(
		append([]certzcrypto.NameConstraintSubtreeFacts(nil), facts.PermittedSubtrees...),
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
// dependencies that do not require fetching or applying a CRL. Actual
// distribution-point scope, issuer resolution, and reason-mask processing are
// P3 responsibilities.
func CRLDistributionPointsDependenciesValid(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	value, present := certificateExtensionValue(certificate, oid.CRLDistributionPoints)
	if !present {
		return true
	}

	facts, err := certzcrypto.DecodeCRLDistributionPointsStrict(value)
	if err != nil {
		return false
	}
	hasAllReasonsPoint := false
	for _, point := range facts.DistributionPoints {
		if !point.ReasonsPresent {
			hasAllReasonsPoint = true
		} else {
			allReasons, invalid := reasonFlagsCoverAll(point.ReasonBits)
			if invalid {
				return false
			}
			if allReasons {
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

func reasonFlagsCoverAll(bits []int) (all bool, invalid bool) {
	var mask uint16
	for _, bit := range bits {
		if bit == 0 || bit < 0 || bit > 8 {
			return false, true
		}
		mask |= 1 << bit
	}
	const allDefinedReasons = uint16(0x1fe) // bits 1 through 8
	return mask == allDefinedReasons, false
}

// PolicyMappingsDependenciesValid checks that Policy Mappings occurs only in
// CA certificates and that neither side of a mapping uses anyPolicy.
func PolicyMappingsDependenciesValid(certificate *x509.Certificate) bool {
	value, present := certificateExtensionValue(certificate, oid.PolicyMappings)
	if certificate == nil {
		return false
	}
	if !present {
		return true
	}
	basicConstraints, valid := basicConstraintsProfileFacts(certificate)
	if !valid || !basicConstraints.CA {
		return false
	}

	mappings, err := certzcrypto.DecodePolicyMappingsStrict(value)
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
	value, present := certificateExtensionValue(certificate, oid.PolicyMappings)
	if certificate == nil {
		return false
	}
	if !present {
		return true
	}

	mappings, err := certzcrypto.DecodePolicyMappingsStrict(value)
	if err != nil {
		return false
	}
	policiesValue, policiesPresent := certificateExtensionValue(certificate, oid.CertificatePolicies)
	if !policiesPresent {
		return false
	}
	policyIdentifiers, err := certzcrypto.DecodeCertificatePolicyIdentifiersStrict(policiesValue)
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
	if !certificateHasExtension(certificate, identifier) {
		return true
	}
	basicConstraints, valid := basicConstraintsProfileFacts(certificate)
	return valid && basicConstraints.CA
}

func basicConstraintsProfileFacts(
	certificate *x509.Certificate,
) (certzcrypto.BasicConstraintsFacts, bool) {
	if certificate == nil {
		return certzcrypto.BasicConstraintsFacts{}, false
	}
	if value, present := certificateExtensionValue(certificate, oid.BasicConstraints); present {
		facts, err := certzcrypto.DecodeBasicConstraintsStrict(value)
		return facts, err == nil
	}

	// Preserve direct domain-test and adapter compatibility for callers that
	// supply typed x509 facts without the raw extension.
	present := certificate.MaxPathLen > 0 || certificate.MaxPathLenZero
	return certzcrypto.BasicConstraintsFacts{
		CA:                       certificate.BasicConstraintsValid && certificate.IsCA,
		PathLenConstraint:        certificate.MaxPathLen,
		PathLenConstraintDecimal: strconv.Itoa(certificate.MaxPathLen),
		PathLenConstraintFitsInt: true,
		PathLenConstraintPresent: present,
	}, true
}

func certificateHasExtension(certificate *x509.Certificate, identifier string) bool {
	_, ok := certificateExtensionValue(certificate, identifier)
	return ok
}

func certificateExtensionValue(certificate *x509.Certificate, identifier string) ([]byte, bool) {
	if certificate == nil {
		return nil, false
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.String() == identifier {
			return extension.Value, true
		}
	}
	return nil, false
}
