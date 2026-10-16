package x509ext

import (
	"github.com/cavoq/PCL/internal/oid"
	"github.com/zmap/zcrypto/x509/pkix"
)

// certificateExtensionCheck decodes one certificate extension value. It
// returns an error for a malformed value and unprocessed=true for a
// well-formed value whose content PCL does not process.
type certificateExtensionCheck func(extValue []byte) (unprocessed bool, err error)

// certificateExtensionChecks covers every extension registered as processable
// in certificates. The certificate node projection uses the same decoders and
// predicates for its malformed and unprocessed markers.
var certificateExtensionChecks = map[string]certificateExtensionCheck{
	oid.KeyUsage:               decodeOnly(DecodeKeyUsage),
	oid.SubjectAlternativeName: decodeOnly(DecodeGeneralNames),
	oid.IssuerAlternativeName:  decodeOnly(DecodeGeneralNames),
	oid.BasicConstraints:       decodeOnly(DecodeBasicConstraints),
	oid.NameConstraints:        decodeOnly(DecodeNameConstraints),
	oid.CRLDistributionPoints:  decodeOnly(DecodeDistributionPoints),
	oid.CertificatePolicies: func(extValue []byte) (bool, error) {
		decoded, err := DecodeCertificatePolicies(extValue)
		return err == nil && CertificatePoliciesContainUnknownQualifier(decoded), err
	},
	oid.PolicyMappings:      decodeOnly(DecodePolicyMappingsStrict),
	oid.PolicyConstraints:   decodeOnly(DecodePolicyConstraintsStrict),
	oid.ExtendedKeyUsage:    decodeOnly(DecodeExtendedKeyUsage),
	oid.InhibitAnyPolicy:    decodeOnly(DecodeInhibitAnyPolicyStrict),
	oid.AuthorityInfoAccess: decodeOnly(DecodeAuthorityInformationAccess),
	oid.FreshestCRL:         decodeOnly(DecodeDistributionPoints),
}

func decodeOnly[T any](decode func([]byte) (T, error)) certificateExtensionCheck {
	return func(extValue []byte) (bool, error) {
		_, err := decode(extValue)
		return false, err
	}
}

// CertificateCriticalExtensionsProcessable reports whether a certificate's
// extensions satisfy RFC 5280 critical-extension handling: no extension OID
// appears twice, and every critical extension is registered as processable in
// certificates, decodes strictly, and has no content PCL does not process.
func CertificateCriticalExtensionsProcessable(extensions []pkix.Extension) bool {
	seen := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		identifier := extension.Id.String()
		if _, duplicate := seen[identifier]; duplicate {
			return false
		}
		seen[identifier] = struct{}{}
	}

	for _, extension := range extensions {
		if !extension.Critical {
			continue
		}
		identifier := extension.Id.String()
		if !oid.ExtensionProcessableAt(identifier, oid.ExtensionInCertificate) {
			return false
		}
		check, ok := certificateExtensionChecks[identifier]
		if !ok {
			return false
		}
		if unprocessed, err := check(extension.Value); err != nil || unprocessed {
			return false
		}
	}
	return true
}

// CertificatePoliciesContainUnknownQualifier reports whether any policy
// carries a qualifier PCL cannot interpret.
func CertificatePoliciesContainUnknownQualifier(decoded CertificatePolicies) bool {
	for _, policy := range decoded.Policies {
		for _, qualifier := range policy.Qualifiers {
			if qualifier.Kind == PolicyQualifierUnknown {
				return true
			}
		}
	}
	return false
}
