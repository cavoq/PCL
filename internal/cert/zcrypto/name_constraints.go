package zcrypto

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type decodedNameConstraints struct {
	Permitted []decodedGeneralSubtree
	Excluded  []decodedGeneralSubtree
	RawDER    []byte
}

type decodedGeneralSubtree struct {
	Base           parsedGeneralName
	Minimum        NonNegativeIntegerValue
	MinimumPresent bool
	MinimumRaw     []byte
	Maximum        NonNegativeIntegerValue
	MaximumPresent bool
	MaximumRaw     []byte
	RawDER         []byte
}

// NameConstraintsFacts is the typed adapter boundary used by certificate
// profile semantics. It intentionally exposes encoded field presence instead
// of requiring domain code to infer it from zero values or policy nodes.
type NameConstraintsFacts struct {
	PermittedSubtrees []NameConstraintSubtreeFacts
	ExcludedSubtrees  []NameConstraintSubtreeFacts
	RawDER            []byte
}

type NameConstraintSubtreeFacts struct {
	BaseTag        int
	BaseRawDER     []byte
	Minimum        int
	MinimumDecimal string
	MinimumFitsInt bool
	MinimumPresent bool
	Maximum        int
	MaximumDecimal string
	MaximumFitsInt bool
	MaximumPresent bool
	RawDER         []byte
}

func ParseNameConstraints(extValue []byte) *node.Node {
	n, err := ParseNameConstraintsStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("nameConstraints", isEmptySequence(extValue), extValue)
}

// ParseNameConstraintsStrict parses all GeneralName alternatives and retains
// exact GeneralSubtree and GeneralName DER. Presence of minimum and maximum is
// represented separately from their integer values.
func ParseNameConstraintsStrict(extValue []byte) (*node.Node, error) {
	decoded, err := decodeNameConstraints(extValue)
	if err != nil {
		return nil, err
	}
	return projectNameConstraints(decoded), nil
}

// DecodeNameConstraintsStrict returns typed, strictly decoded facts for the
// certificate domain. Non-profile minimum and maximum values remain valid
// representation facts so semantic code can report them explicitly.
func DecodeNameConstraintsStrict(extValue []byte) (NameConstraintsFacts, error) {
	decoded, err := decodeNameConstraints(extValue)
	if err != nil {
		return NameConstraintsFacts{}, err
	}
	return nameConstraintsFacts(decoded), nil
}

func nameConstraintsFacts(decoded decodedNameConstraints) NameConstraintsFacts {
	facts := NameConstraintsFacts{RawDER: append([]byte(nil), decoded.RawDER...)}
	for _, subtree := range decoded.Permitted {
		facts.PermittedSubtrees = append(
			facts.PermittedSubtrees,
			nameConstraintSubtreeFacts(subtree),
		)
	}
	for _, subtree := range decoded.Excluded {
		facts.ExcludedSubtrees = append(
			facts.ExcludedSubtrees,
			nameConstraintSubtreeFacts(subtree),
		)
	}
	return facts
}

func nameConstraintSubtreeFacts(decoded decodedGeneralSubtree) NameConstraintSubtreeFacts {
	return NameConstraintSubtreeFacts{
		BaseTag:        decoded.Base.Tag,
		BaseRawDER:     append([]byte(nil), decoded.Base.RawDER...),
		Minimum:        decoded.Minimum.Int,
		MinimumDecimal: decoded.Minimum.Decimal,
		MinimumFitsInt: decoded.Minimum.FitsInt,
		MinimumPresent: decoded.MinimumPresent,
		Maximum:        decoded.Maximum.Int,
		MaximumDecimal: decoded.Maximum.Decimal,
		MaximumFitsInt: decoded.Maximum.FitsInt,
		MaximumPresent: decoded.MaximumPresent,
		RawDER:         append([]byte(nil), decoded.RawDER...),
	}
}

func decodeNameConstraints(extValue []byte) (decodedNameConstraints, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return decodedNameConstraints{}, fmt.Errorf("invalid NameConstraints sequence")
	}
	if sequence.Empty() {
		return decodedNameConstraints{}, fmt.Errorf("NameConstraints must not be empty")
	}

	decoded := decodedNameConstraints{RawDER: append([]byte(nil), extValue...)}
	permittedTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	excludedTag := cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()
	if sequence.PeekASN1Tag(permittedTag) {
		var permitted cryptobyte.String
		if !sequence.ReadASN1(&permitted, permittedTag) || permitted.Empty() {
			return decodedNameConstraints{}, fmt.Errorf("invalid permittedSubtrees")
		}
		subtrees, err := decodeGeneralSubtrees(&permitted, "permittedSubtrees")
		if err != nil {
			return decodedNameConstraints{}, err
		}
		decoded.Permitted = subtrees
	}
	if sequence.PeekASN1Tag(excludedTag) {
		var excluded cryptobyte.String
		if !sequence.ReadASN1(&excluded, excludedTag) || excluded.Empty() {
			return decodedNameConstraints{}, fmt.Errorf("invalid excludedSubtrees")
		}
		subtrees, err := decodeGeneralSubtrees(&excluded, "excludedSubtrees")
		if err != nil {
			return decodedNameConstraints{}, err
		}
		decoded.Excluded = subtrees
	}
	if !sequence.Empty() {
		return decodedNameConstraints{}, fmt.Errorf("duplicate, out-of-order, or unknown NameConstraints field")
	}
	return decoded, nil
}

func decodeGeneralSubtrees(input *cryptobyte.String, field string) ([]decodedGeneralSubtree, error) {
	var subtrees []decodedGeneralSubtree
	for index := 0; !input.Empty(); index++ {
		var encoded cryptobyte.String
		if !input.ReadASN1Element(&encoded, cryptobyte_asn1.SEQUENCE) {
			return nil, fmt.Errorf("invalid GeneralSubtree %d in %s", index, field)
		}
		subtree, err := decodeGeneralSubtree(encoded, index, field)
		if err != nil {
			return nil, err
		}
		subtrees = append(subtrees, subtree)
	}
	return subtrees, nil
}

func decodeGeneralSubtree(
	encoded cryptobyte.String,
	index int,
	field string,
) (decodedGeneralSubtree, error) {
	input := encoded
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return decodedGeneralSubtree{}, fmt.Errorf("invalid GeneralSubtree %d in %s", index, field)
	}
	base, err := readGeneralNameWithValidation(&sequence, validateNameConstraintGeneralName)
	if err != nil {
		return decodedGeneralSubtree{}, fmt.Errorf("invalid base in GeneralSubtree %d of %s: %w", index, field, err)
	}

	decoded := decodedGeneralSubtree{
		Base:   base,
		RawDER: append([]byte(nil), encoded...),
	}
	minimumTag := cryptobyte_asn1.Tag(0).ContextSpecific()
	maximumTag := cryptobyte_asn1.Tag(1).ContextSpecific()
	if sequence.PeekASN1Tag(minimumTag) {
		value, raw, err := readImplicitNonNegativeInteger(&sequence, minimumTag)
		if err != nil {
			return decodedGeneralSubtree{}, fmt.Errorf("invalid minimum in GeneralSubtree %d of %s: %w", index, field, err)
		}
		if value.Decimal == "0" {
			return decodedGeneralSubtree{}, fmt.Errorf(
				"minimum in GeneralSubtree %d of %s explicitly encodes DEFAULT zero",
				index,
				field,
			)
		}
		decoded.Minimum = value
		decoded.MinimumPresent = true
		decoded.MinimumRaw = raw
	}
	if sequence.PeekASN1Tag(maximumTag) {
		value, raw, err := readImplicitNonNegativeInteger(&sequence, maximumTag)
		if err != nil {
			return decodedGeneralSubtree{}, fmt.Errorf("invalid maximum in GeneralSubtree %d of %s: %w", index, field, err)
		}
		decoded.Maximum = value
		decoded.MaximumPresent = true
		decoded.MaximumRaw = raw
	}
	if !sequence.Empty() {
		return decodedGeneralSubtree{}, fmt.Errorf(
			"duplicate, out-of-order, or unknown field in GeneralSubtree %d of %s",
			index,
			field,
		)
	}
	return decoded, nil
}

func projectNameConstraints(decoded decodedNameConstraints) *node.Node {
	n := node.New("nameConstraints", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	if nameConstraintsContainUnsupportedNameForm(decoded) {
		// The representation is valid, but the bounded matching domain does not
		// implement every GeneralName comparison. Critical-extension handling
		// uses this marker to reject constraints it cannot enforce.
		n.Children["unprocessed"] = node.New("unprocessed", true)
	}
	if len(decoded.Permitted) > 0 {
		n.Children["permittedSubtrees"] = projectGeneralSubtrees(
			"permittedSubtrees",
			decoded.Permitted,
		)
	}
	if len(decoded.Excluded) > 0 {
		n.Children["excludedSubtrees"] = projectGeneralSubtrees(
			"excludedSubtrees",
			decoded.Excluded,
		)
	}
	return n
}

func nameConstraintsContainUnsupportedNameForm(decoded decodedNameConstraints) bool {
	for _, subtrees := range [][]decodedGeneralSubtree{decoded.Permitted, decoded.Excluded} {
		for _, subtree := range subtrees {
			switch subtree.Base.Tag {
			case 1, 2, 6, 7: // rfc822Name, dNSName, URI, iPAddress
			default:
				return true
			}
		}
	}
	return false
}

func projectGeneralSubtrees(name string, decoded []decodedGeneralSubtree) *node.Node {
	n := node.New(name, nil)
	n.Children["count"] = node.New("count", len(decoded))
	typeCounts := make(map[int]int)
	for index, subtree := range decoded {
		key := strconv.Itoa(index)
		projected := projectGeneralSubtree(key, subtree)
		n.Children[key] = projected

		typeName := generalNameType(subtree.Base.Tag)
		typeCollection := n.Children[typeName]
		if typeCollection == nil {
			typeCollection = node.New(typeName, nil)
			n.Children[typeName] = typeCollection
		}
		typeIndex := strconv.Itoa(typeCounts[subtree.Base.Tag])
		typeCollection.Children[typeIndex] = aliasGeneralNameNode(typeIndex, projected)
		typeCounts[subtree.Base.Tag]++
	}
	return n
}

func projectGeneralSubtree(name string, decoded decodedGeneralSubtree) *node.Node {
	base := buildNameConstraintGeneralName("base", decoded.Base)
	n := node.New(name, cloneGeneralNameScalar(base.Value))
	n.Children["base"] = base
	n.Children["value"] = node.New("value", cloneGeneralNameScalar(base.Value))
	n.Children["type"] = node.New("type", generalNameType(decoded.Base.Tag))
	n.Children["tag"] = node.New("tag", decoded.Base.Tag)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["minimum"] = integerFactNode(
		"minimum",
		decoded.Minimum,
		decoded.MinimumPresent,
		decoded.MinimumRaw,
	)
	n.Children["minimumPresent"] = node.New("minimumPresent", decoded.MinimumPresent)
	n.Children["maximumPresent"] = node.New("maximumPresent", decoded.MaximumPresent)
	if decoded.MinimumPresent {
		n.Children["min"] = integerFactNode("min", decoded.Minimum, true, decoded.MinimumRaw)
	}
	if decoded.MaximumPresent {
		n.Children["maximum"] = integerFactNode(
			"maximum",
			decoded.Maximum,
			true,
			decoded.MaximumRaw,
		)
		n.Children["max"] = integerFactNode("max", decoded.Maximum, true, decoded.MaximumRaw)
	}
	return n
}

func integerFactNode(
	name string,
	value NonNegativeIntegerValue,
	present bool,
	raw []byte,
) *node.Node {
	var scalar any = 0
	if present {
		scalar = integerValueScalar(value)
	}
	n := node.New(name, scalar)
	n.Children["present"] = node.New("present", present)
	if present {
		n.Children["raw"] = node.New("raw", append([]byte(nil), raw...))
		n.Children["decimal"] = node.New("decimal", value.Decimal)
		n.Children["fitsInt"] = node.New("fitsInt", value.FitsInt)
	}
	return n
}

func buildNameConstraintGeneralName(name string, parsed parsedGeneralName) *node.Node {
	n := buildParsedGeneralName(name, parsed)
	if parsed.Tag != 7 {
		return n
	}

	half := len(parsed.RawValue) / 2
	addressBytes := append([]byte(nil), parsed.RawValue[:half]...)
	maskBytes := append([]byte(nil), parsed.RawValue[half:]...)
	address := net.IP(addressBytes)
	mask := net.IPMask(maskBytes)
	network := (&net.IPNet{IP: address, Mask: mask}).String()
	n.Value = network
	n.Children["value"] = node.New("value", network)
	n.Children["address"] = node.New("address", address.String())
	n.Children["mask"] = node.New("mask", append([]byte(nil), maskBytes...))
	if prefixLength, bits := mask.Size(); bits != 0 {
		n.Children["prefixLength"] = node.New("prefixLength", prefixLength)
	}
	return n
}
