package x509ext

import (
	stdasn1 "encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PolicyMapping is the lossless semantic payload of one PolicyMappings pair.
// RawDER contains the complete pair SEQUENCE.
type PolicyMapping struct {
	IssuerDomainPolicy  string
	SubjectDomainPolicy string
	RawDER              []byte
}

// DecodePolicyMappingsStrict exposes typed mapping facts to the certificate
// domain without requiring it to duplicate ASN.1 parsing or traverse nodes.
func DecodePolicyMappingsStrict(extValue []byte) ([]PolicyMapping, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid PolicyMappings sequence")
	}
	if sequence.Empty() {
		return nil, fmt.Errorf("PolicyMappings must not be empty")
	}

	var mappings []PolicyMapping
	for index := 0; !sequence.Empty(); index++ {
		var encodedMapping cryptobyte.String
		if !sequence.ReadASN1Element(&encodedMapping, cryptobyte_asn1.SEQUENCE) {
			return nil, fmt.Errorf("invalid PolicyMapping %d", index)
		}
		mapping := encodedMapping
		var fields cryptobyte.String
		if !mapping.ReadASN1(&fields, cryptobyte_asn1.SEQUENCE) || !mapping.Empty() {
			return nil, fmt.Errorf("invalid PolicyMapping %d", index)
		}

		var issuerPolicy, subjectPolicy stdasn1.ObjectIdentifier
		if !fields.ReadASN1ObjectIdentifier(&issuerPolicy) {
			return nil, fmt.Errorf("invalid issuerDomainPolicy in PolicyMapping %d", index)
		}
		if !fields.ReadASN1ObjectIdentifier(&subjectPolicy) || !fields.Empty() {
			return nil, fmt.Errorf("invalid subjectDomainPolicy in PolicyMapping %d", index)
		}
		mappings = append(mappings, PolicyMapping{
			IssuerDomainPolicy:  issuerPolicy.String(),
			SubjectDomainPolicy: subjectPolicy.String(),
			RawDER:              append([]byte(nil), encodedMapping...),
		})
	}
	return mappings, nil
}

// PolicyConstraints preserves presence independently from zero values.
type PolicyConstraints struct {
	RequireExplicitPolicy        int
	RequireExplicitPolicyDecimal string
	RequireExplicitPolicyFitsInt bool
	RequireExplicitPolicyPresent bool
	InhibitPolicyMapping         int
	InhibitPolicyMappingDecimal  string
	InhibitPolicyMappingFitsInt  bool
	InhibitPolicyMappingPresent  bool
	RequireExplicitPolicyRaw     []byte
	InhibitPolicyMappingRaw      []byte
	RawDER                       []byte
}

// DecodePolicyConstraintsStrict returns both optional counters without
// conflating an encoded zero with absence.
func DecodePolicyConstraintsStrict(extValue []byte) (PolicyConstraints, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return PolicyConstraints{}, fmt.Errorf("invalid PolicyConstraints sequence")
	}
	if sequence.Empty() {
		return PolicyConstraints{}, fmt.Errorf("PolicyConstraints must not be empty")
	}

	decoded := PolicyConstraints{RawDER: append([]byte(nil), extValue...)}
	requireTag := cryptobyte_asn1.Tag(0).ContextSpecific()
	inhibitTag := cryptobyte_asn1.Tag(1).ContextSpecific()
	if sequence.PeekASN1Tag(requireTag) {
		value, raw, err := readImplicitNonNegativeInteger(&sequence, requireTag)
		if err != nil {
			return PolicyConstraints{}, fmt.Errorf("invalid requireExplicitPolicy: %w", err)
		}
		decoded.RequireExplicitPolicy = value.Int
		decoded.RequireExplicitPolicyDecimal = value.Decimal
		decoded.RequireExplicitPolicyFitsInt = value.FitsInt
		decoded.RequireExplicitPolicyPresent = true
		decoded.RequireExplicitPolicyRaw = raw
	}
	if sequence.PeekASN1Tag(inhibitTag) {
		value, raw, err := readImplicitNonNegativeInteger(&sequence, inhibitTag)
		if err != nil {
			return PolicyConstraints{}, fmt.Errorf("invalid inhibitPolicyMapping: %w", err)
		}
		decoded.InhibitPolicyMapping = value.Int
		decoded.InhibitPolicyMappingDecimal = value.Decimal
		decoded.InhibitPolicyMappingFitsInt = value.FitsInt
		decoded.InhibitPolicyMappingPresent = true
		decoded.InhibitPolicyMappingRaw = raw
	}
	if !sequence.Empty() {
		return PolicyConstraints{}, fmt.Errorf("duplicate, out-of-order, or unknown PolicyConstraints field")
	}
	return decoded, nil
}

// DecodeInhibitAnyPolicyStrict decodes the SkipCerts value used by the path
// policy domain.
func DecodeInhibitAnyPolicyStrict(extValue []byte) (NonNegativeInteger, error) {
	value, err := DecodeNonNegativeInteger(extValue)
	if err != nil {
		return NonNegativeInteger{}, fmt.Errorf("invalid InhibitAnyPolicy SkipCerts: %w", err)
	}
	return value, nil
}
