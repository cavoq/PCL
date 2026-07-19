package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"strconv"

	"github.com/cavoq/PCL/internal/node"
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

func ParsePolicyMappings(extValue []byte) *node.Node {
	n, err := ParsePolicyMappingsStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("policyMappings", isEmptySequence(extValue), extValue)
}

func ParsePolicyMappingsStrict(extValue []byte) (*node.Node, error) {
	mappings, err := DecodePolicyMappingsStrict(extValue)
	if err != nil {
		return nil, err
	}
	return projectPolicyMappings(extValue, mappings), nil
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
		mapping := cryptobyte.String(encodedMapping)
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

func projectPolicyMappings(raw []byte, mappings []PolicyMapping) *node.Node {
	n := node.New("policyMappings", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), raw...))
	n.Children["count"] = node.New("count", len(mappings))
	mappingsNode := node.New("mappings", nil)
	n.Children["mappings"] = mappingsNode
	for index, mapping := range mappings {
		key := strconv.Itoa(index)
		mappingNode := node.New(key, nil)
		mappingNode.Children["issuerDomainPolicy"] = node.New(
			"issuerDomainPolicy",
			mapping.IssuerDomainPolicy,
		)
		mappingNode.Children["subjectDomainPolicy"] = node.New(
			"subjectDomainPolicy",
			mapping.SubjectDomainPolicy,
		)
		mappingNode.Children["raw"] = node.New("raw", append([]byte(nil), mapping.RawDER...))
		mappingsNode.Children[key] = mappingNode
	}
	return n
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

func ParsePolicyConstraints(extValue []byte) *node.Node {
	n, err := ParsePolicyConstraintsStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("policyConstraints", isEmptySequence(extValue), extValue)
}

func ParsePolicyConstraintsStrict(extValue []byte) (*node.Node, error) {
	decoded, err := DecodePolicyConstraintsStrict(extValue)
	if err != nil {
		return nil, err
	}
	return projectPolicyConstraints(decoded), nil
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

func projectPolicyConstraints(decoded PolicyConstraints) *node.Node {
	n := node.New("policyConstraints", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["requireExplicitPolicyPresent"] = node.New(
		"requireExplicitPolicyPresent",
		decoded.RequireExplicitPolicyPresent,
	)
	n.Children["inhibitPolicyMappingPresent"] = node.New(
		"inhibitPolicyMappingPresent",
		decoded.InhibitPolicyMappingPresent,
	)
	if decoded.RequireExplicitPolicyPresent {
		integer := NonNegativeIntegerValue{
			Int:     decoded.RequireExplicitPolicy,
			Decimal: decoded.RequireExplicitPolicyDecimal,
			FitsInt: decoded.RequireExplicitPolicyFitsInt,
		}
		value := node.New("requireExplicitPolicy", integerValueScalar(integer))
		value.Children["raw"] = node.New(
			"raw",
			append([]byte(nil), decoded.RequireExplicitPolicyRaw...),
		)
		value.Children["decimal"] = node.New("decimal", integer.Decimal)
		value.Children["fitsInt"] = node.New("fitsInt", integer.FitsInt)
		n.Children["requireExplicitPolicy"] = value
	}
	if decoded.InhibitPolicyMappingPresent {
		integer := NonNegativeIntegerValue{
			Int:     decoded.InhibitPolicyMapping,
			Decimal: decoded.InhibitPolicyMappingDecimal,
			FitsInt: decoded.InhibitPolicyMappingFitsInt,
		}
		value := node.New("inhibitPolicyMapping", integerValueScalar(integer))
		value.Children["raw"] = node.New(
			"raw",
			append([]byte(nil), decoded.InhibitPolicyMappingRaw...),
		)
		value.Children["decimal"] = node.New("decimal", integer.Decimal)
		value.Children["fitsInt"] = node.New("fitsInt", integer.FitsInt)
		n.Children["inhibitPolicyMapping"] = value
	}
	return n
}

func ParseInhibitAnyPolicy(extValue []byte) *node.Node {
	n, err := ParseInhibitAnyPolicyStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("inhibitAnyPolicy", false, extValue)
}

func ParseInhibitAnyPolicyStrict(extValue []byte) (*node.Node, error) {
	skipCerts, err := DecodeInhibitAnyPolicyStrict(extValue)
	if err != nil {
		return nil, err
	}
	n := node.New("inhibitAnyPolicy", integerValueScalar(skipCerts))
	skipCertsNode := node.New("skipCerts", integerValueScalar(skipCerts))
	skipCertsNode.Children["decimal"] = node.New("decimal", skipCerts.Decimal)
	skipCertsNode.Children["fitsInt"] = node.New("fitsInt", skipCerts.FitsInt)
	n.Children["skipCerts"] = skipCertsNode
	n.Children["raw"] = node.New("raw", append([]byte(nil), extValue...))
	return n, nil
}

// DecodeInhibitAnyPolicyStrict decodes the SkipCerts value used by the path
// policy domain.
func DecodeInhibitAnyPolicyStrict(extValue []byte) (NonNegativeIntegerValue, error) {
	value, err := decodeSingleNonNegativeInteger(extValue)
	if err != nil {
		return NonNegativeIntegerValue{}, fmt.Errorf("invalid InhibitAnyPolicy SkipCerts: %w", err)
	}
	return value, nil
}
