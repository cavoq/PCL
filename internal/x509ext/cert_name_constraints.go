package x509ext

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// NameConstraints is a decoded Name Constraints extension with the
// permitted and excluded subtrees in encoding order.
type NameConstraints struct {
	Permitted []GeneralSubtree
	Excluded  []GeneralSubtree
	RawDER    []byte
}

// GeneralSubtree is one subtree of a Name Constraints extension. Minimum
// and maximum record whether they were encoded and their exact encoding.
type GeneralSubtree struct {
	Base           GeneralName
	Minimum        NonNegativeInteger
	MinimumPresent bool
	MinimumRaw     []byte
	Maximum        NonNegativeInteger
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

// NameConstraintSubtreeFacts is the view of a GeneralSubtree that name
// constraint processing uses.
type NameConstraintSubtreeFacts struct {
	BaseTag    int
	BaseRawDER []byte
	// BaseRawValue holds the GeneralName contents; for a directoryName base
	// it is the DER encoding of the Name.
	BaseRawValue   []byte
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

// DecodeNameConstraintsStrict returns typed, strictly decoded facts for the
// certificate domain. Non-profile minimum and maximum values remain valid
// representation facts so semantic code can report them explicitly.
func DecodeNameConstraintsStrict(extValue []byte) (NameConstraintsFacts, error) {
	decoded, err := DecodeNameConstraints(extValue)
	if err != nil {
		return NameConstraintsFacts{}, err
	}
	return nameConstraintsFacts(decoded), nil
}

func nameConstraintsFacts(decoded NameConstraints) NameConstraintsFacts {
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

func nameConstraintSubtreeFacts(decoded GeneralSubtree) NameConstraintSubtreeFacts {
	return NameConstraintSubtreeFacts{
		BaseTag:        decoded.Base.Tag,
		BaseRawDER:     append([]byte(nil), decoded.Base.RawDER...),
		BaseRawValue:   append([]byte(nil), decoded.Base.RawValue...),
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

// DecodeNameConstraints decodes a Name Constraints extension value. It
// rejects encodings DER forbids, such as an explicit DEFAULT minimum.
func DecodeNameConstraints(extValue []byte) (NameConstraints, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return NameConstraints{}, fmt.Errorf("invalid NameConstraints sequence")
	}
	if sequence.Empty() {
		return NameConstraints{}, fmt.Errorf("NameConstraints must not be empty")
	}

	decoded := NameConstraints{RawDER: append([]byte(nil), extValue...)}
	permittedTag := cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	excludedTag := cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()
	if sequence.PeekASN1Tag(permittedTag) {
		var permitted cryptobyte.String
		if !sequence.ReadASN1(&permitted, permittedTag) || permitted.Empty() {
			return NameConstraints{}, fmt.Errorf("invalid permittedSubtrees")
		}
		subtrees, err := decodeGeneralSubtrees(&permitted, "permittedSubtrees")
		if err != nil {
			return NameConstraints{}, err
		}
		decoded.Permitted = subtrees
	}
	if sequence.PeekASN1Tag(excludedTag) {
		var excluded cryptobyte.String
		if !sequence.ReadASN1(&excluded, excludedTag) || excluded.Empty() {
			return NameConstraints{}, fmt.Errorf("invalid excludedSubtrees")
		}
		subtrees, err := decodeGeneralSubtrees(&excluded, "excludedSubtrees")
		if err != nil {
			return NameConstraints{}, err
		}
		decoded.Excluded = subtrees
	}
	if !sequence.Empty() {
		return NameConstraints{}, fmt.Errorf("duplicate, out-of-order, or unknown NameConstraints field")
	}
	return decoded, nil
}

func decodeGeneralSubtrees(input *cryptobyte.String, field string) ([]GeneralSubtree, error) {
	var subtrees []GeneralSubtree
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
) (GeneralSubtree, error) {
	input := encoded
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return GeneralSubtree{}, fmt.Errorf("invalid GeneralSubtree %d in %s", index, field)
	}
	base, err := ReadNameConstraintGeneralName(&sequence)
	if err != nil {
		return GeneralSubtree{}, fmt.Errorf("invalid base in GeneralSubtree %d of %s: %w", index, field, err)
	}

	decoded := GeneralSubtree{
		Base:   base,
		RawDER: append([]byte(nil), encoded...),
	}
	minimumTag := cryptobyte_asn1.Tag(0).ContextSpecific()
	maximumTag := cryptobyte_asn1.Tag(1).ContextSpecific()
	if sequence.PeekASN1Tag(minimumTag) {
		value, raw, err := readImplicitNonNegativeInteger(&sequence, minimumTag)
		if err != nil {
			return GeneralSubtree{}, fmt.Errorf("invalid minimum in GeneralSubtree %d of %s: %w", index, field, err)
		}
		if value.Decimal == "0" {
			return GeneralSubtree{}, fmt.Errorf(
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
			return GeneralSubtree{}, fmt.Errorf("invalid maximum in GeneralSubtree %d of %s: %w", index, field, err)
		}
		decoded.Maximum = value
		decoded.MaximumPresent = true
		decoded.MaximumRaw = raw
	}
	if !sequence.Empty() {
		return GeneralSubtree{}, fmt.Errorf(
			"duplicate, out-of-order, or unknown field in GeneralSubtree %d of %s",
			index,
			field,
		)
	}
	return decoded, nil
}

// NameConstraintsContainUnsupportedNameForm reports whether a subtree uses
// a name form that name constraint processing does not support.
func NameConstraintsContainUnsupportedNameForm(decoded NameConstraints) bool {
	for _, subtrees := range [][]GeneralSubtree{decoded.Permitted, decoded.Excluded} {
		for _, subtree := range subtrees {
			switch subtree.Base.Tag {
			case 1, 2, 4, 6, 7: // rfc822Name, dNSName, directoryName, URI, iPAddress
			default:
				return true
			}
		}
	}
	return false
}
