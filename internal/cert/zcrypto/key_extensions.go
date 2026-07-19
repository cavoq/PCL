package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const anyExtendedKeyUsageOID = "2.5.29.37.0"

type decodedKeyUsage struct {
	Value      int
	BitLength  int
	UnusedBits int
	RawDER     []byte
	RawValue   []byte
}

// ParseKeyUsage retains the compatibility convention of returning a node
// whose malformed child is true when strict parsing fails.
func ParseKeyUsage(extValue []byte) *node.Node {
	n, err := ParseKeyUsageStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("keyUsage", false, extValue)
}

// ParseKeyUsageStrict parses exactly one RFC 5280 KeyUsage BIT STRING.
func ParseKeyUsageStrict(extValue []byte) (*node.Node, error) {
	decoded, err := decodeKeyUsage(extValue)
	if err != nil {
		return nil, err
	}
	return projectKeyUsage(decoded), nil
}

func decodeKeyUsage(extValue []byte) (decodedKeyUsage, error) {
	input := cryptobyte.String(extValue)
	var bits stdasn1.BitString
	if !input.ReadASN1BitString(&bits) || !input.Empty() {
		return decodedKeyUsage{}, fmt.Errorf("invalid KeyUsage BIT STRING")
	}
	if bits.BitLength > 9 {
		return decodedKeyUsage{}, fmt.Errorf("KeyUsage contains undefined bit %d", bits.BitLength-1)
	}
	// A DER encoding of a named bit list omits trailing zero bits. The empty
	// list remains structurally representable so profile policy can report the
	// RFC requirement that at least one bit be asserted.
	if bits.BitLength > 0 && bits.At(bits.BitLength-1) == 0 {
		return decodedKeyUsage{}, fmt.Errorf("KeyUsage has non-canonical trailing zero bits")
	}

	value := 0
	for bit := 0; bit < bits.BitLength; bit++ {
		if bits.At(bit) != 0 {
			value |= 1 << bit
		}
	}
	return decodedKeyUsage{
		Value:      value,
		BitLength:  bits.BitLength,
		UnusedBits: len(bits.Bytes)*8 - bits.BitLength,
		RawDER:     append([]byte(nil), extValue...),
		RawValue:   append([]byte(nil), bits.Bytes...),
	}, nil
}

func projectKeyUsage(decoded decodedKeyUsage) *node.Node {
	n := node.New("keyUsage", decoded.Value)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), decoded.RawValue...))
	n.Children["bitLength"] = node.New("bitLength", decoded.BitLength)
	n.Children["unusedBits"] = node.New("unusedBits", decoded.UnusedBits)

	definitions := []struct {
		bit  int
		name string
	}{
		{0, "digitalSignature"},
		{1, "contentCommitment"},
		{2, "keyEncipherment"},
		{3, "dataEncipherment"},
		{4, "keyAgreement"},
		{5, "keyCertSign"},
		{6, "cRLSign"},
		{7, "encipherOnly"},
		{8, "decipherOnly"},
	}
	for _, definition := range definitions {
		set := decoded.Value&(1<<definition.bit) != 0
		n.Children[definition.name] = node.New(definition.name, set)
	}
	// nonRepudiation is the original RFC 5280 spelling and remains an alias
	// of the later X.509 name contentCommitment.
	n.Children["nonRepudiation"] = node.New(
		"nonRepudiation",
		decoded.Value&(1<<1) != 0,
	)
	return n
}

type decodedBasicConstraints struct {
	CA                       bool
	CAPresent                bool
	PathLenConstraint        NonNegativeIntegerValue
	PathLenConstraintPresent bool
	RawDER                   []byte
}

// BasicConstraintsFacts is the strict typed boundary used by certificate
// profile semantics. The decimal path length remains exact even when it is
// larger than a native counter.
type BasicConstraintsFacts struct {
	CA                       bool
	CAPresent                bool
	PathLenConstraint        int
	PathLenConstraintDecimal string
	PathLenConstraintFitsInt bool
	PathLenConstraintPresent bool
	RawDER                   []byte
}

func ParseBasicConstraints(extValue []byte) *node.Node {
	n, err := ParseBasicConstraintsStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("basicConstraints", isEmptySequence(extValue), extValue)
}

// ParseBasicConstraintsStrict parses exactly one BasicConstraints sequence,
// preserving whether its DEFAULT and OPTIONAL fields were encoded.
func ParseBasicConstraintsStrict(extValue []byte) (*node.Node, error) {
	decoded, err := decodeBasicConstraints(extValue)
	if err != nil {
		return nil, err
	}
	return projectBasicConstraints(decoded), nil
}

// DecodeBasicConstraintsStrict exposes strictly decoded presence and counter
// facts without relying on the underlying x509 library's native int fields.
func DecodeBasicConstraintsStrict(extValue []byte) (BasicConstraintsFacts, error) {
	decoded, err := decodeBasicConstraints(extValue)
	if err != nil {
		return BasicConstraintsFacts{}, err
	}
	return BasicConstraintsFacts{
		CA:                       decoded.CA,
		CAPresent:                decoded.CAPresent,
		PathLenConstraint:        decoded.PathLenConstraint.Int,
		PathLenConstraintDecimal: decoded.PathLenConstraint.Decimal,
		PathLenConstraintFitsInt: decoded.PathLenConstraint.FitsInt,
		PathLenConstraintPresent: decoded.PathLenConstraintPresent,
		RawDER:                   append([]byte(nil), decoded.RawDER...),
	}, nil
}

func decodeBasicConstraints(extValue []byte) (decodedBasicConstraints, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return decodedBasicConstraints{}, fmt.Errorf("invalid BasicConstraints sequence")
	}

	decoded := decodedBasicConstraints{RawDER: append([]byte(nil), extValue...)}
	if sequence.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !sequence.ReadASN1Boolean(&decoded.CA) {
			return decodedBasicConstraints{}, fmt.Errorf("invalid BasicConstraints cA boolean")
		}
		if !decoded.CA {
			return decodedBasicConstraints{}, fmt.Errorf(
				"BasicConstraints explicitly encodes DEFAULT cA false",
			)
		}
		decoded.CAPresent = true
	}
	if sequence.PeekASN1Tag(cryptobyte_asn1.INTEGER) {
		var encoded cryptobyte.String
		if !sequence.ReadASN1Element(&encoded, cryptobyte_asn1.INTEGER) {
			return decodedBasicConstraints{}, fmt.Errorf("invalid pathLenConstraint")
		}
		value, err := decodeSingleNonNegativeInteger(encoded)
		if err != nil {
			return decodedBasicConstraints{}, fmt.Errorf("invalid pathLenConstraint: %w", err)
		}
		decoded.PathLenConstraint = value
		decoded.PathLenConstraintPresent = true
	}
	if !sequence.Empty() {
		return decodedBasicConstraints{}, fmt.Errorf("unexpected BasicConstraints field")
	}
	return decoded, nil
}

func projectBasicConstraints(decoded decodedBasicConstraints) *node.Node {
	n := node.New("basicConstraints", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["cA"] = node.New("cA", decoded.CA)
	n.Children["cAPresent"] = node.New("cAPresent", decoded.CAPresent)
	n.Children["pathLenConstraintPresent"] = node.New(
		"pathLenConstraintPresent",
		decoded.PathLenConstraintPresent,
	)
	if decoded.PathLenConstraintPresent {
		pathLen := node.New(
			"pathLenConstraint",
			integerValueScalar(decoded.PathLenConstraint),
		)
		pathLen.Children["decimal"] = node.New("decimal", decoded.PathLenConstraint.Decimal)
		pathLen.Children["fitsInt"] = node.New("fitsInt", decoded.PathLenConstraint.FitsInt)
		n.Children["pathLenConstraint"] = pathLen
	}
	return n
}

type decodedExtendedKeyUsage struct {
	Usages []decodedKeyPurpose
	RawDER []byte
}

type decodedKeyPurpose struct {
	OID    string
	RawDER []byte
}

func ParseExtKeyUsage(extValue []byte) *node.Node {
	n, err := ParseExtKeyUsageStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNodeWithRaw("extKeyUsage", isEmptySequence(extValue), extValue)
}

// ParseExtKeyUsageStrict projects every KeyPurposeId, including anyExtendedKeyUsage
// and identifiers unknown to the underlying x509 library.
func ParseExtKeyUsageStrict(extValue []byte) (*node.Node, error) {
	decoded, err := decodeExtendedKeyUsage(extValue)
	if err != nil {
		return nil, err
	}
	return projectExtendedKeyUsage(decoded), nil
}

// DecodeExtendedKeyUsageOIDsStrict returns every KeyPurposeId in wire order.
// Reading the identifiers from the extension DER avoids losing usages that the
// underlying x509 library recognizes but PCL does not assign a friendly name.
func DecodeExtendedKeyUsageOIDsStrict(extValue []byte) ([]string, error) {
	decoded, err := decodeExtendedKeyUsage(extValue)
	if err != nil {
		return nil, err
	}

	identifiers := make([]string, len(decoded.Usages))
	for index, usage := range decoded.Usages {
		identifiers[index] = usage.OID
	}
	return identifiers, nil
}

func decodeExtendedKeyUsage(extValue []byte) (decodedExtendedKeyUsage, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return decodedExtendedKeyUsage{}, fmt.Errorf("invalid ExtKeyUsageSyntax sequence")
	}
	if sequence.Empty() {
		return decodedExtendedKeyUsage{}, fmt.Errorf("ExtKeyUsageSyntax must not be empty")
	}

	decoded := decodedExtendedKeyUsage{RawDER: append([]byte(nil), extValue...)}
	for index := 0; !sequence.Empty(); index++ {
		var encoded cryptobyte.String
		if !sequence.ReadASN1Element(&encoded, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			return decodedExtendedKeyUsage{}, fmt.Errorf("invalid KeyPurposeId %d", index)
		}
		value := encoded
		var identifier stdasn1.ObjectIdentifier
		if !value.ReadASN1ObjectIdentifier(&identifier) || !value.Empty() {
			return decodedExtendedKeyUsage{}, fmt.Errorf("invalid KeyPurposeId %d", index)
		}
		decoded.Usages = append(decoded.Usages, decodedKeyPurpose{
			OID:    identifier.String(),
			RawDER: append([]byte(nil), encoded...),
		})
	}
	return decoded, nil
}

func projectExtendedKeyUsage(decoded decodedExtendedKeyUsage) *node.Node {
	n := node.New("extKeyUsage", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["count"] = node.New("count", len(decoded.Usages))
	usages := node.New("usages", nil)
	unknown := node.New("unknown", nil)
	n.Children["usages"] = usages

	unknownCount := 0
	for index, decodedUsage := range decoded.Usages {
		key := strconv.Itoa(index)
		usage := node.New(key, decodedUsage.OID)
		usage.Children["oid"] = node.New("oid", decodedUsage.OID)
		usage.Children["raw"] = node.New("raw", append([]byte(nil), decodedUsage.RawDER...))
		if friendlyName, known := extendedKeyUsageName(decodedUsage.OID); known {
			usage.Children["name"] = node.New("name", friendlyName)
			n.Children[friendlyName] = node.New(friendlyName, true)
		} else {
			unknownKey := strconv.Itoa(unknownCount)
			unknown.Children[unknownKey] = &node.Node{
				Name:     unknownKey,
				Value:    usage.Value,
				Children: usage.Children,
			}
			unknownCount++
		}
		usages.Children[key] = usage
		n.Children[decodedUsage.OID] = usage
	}
	if unknownCount > 0 {
		unknown.Children["count"] = node.New("count", unknownCount)
		n.Children["unknown"] = unknown
	}
	return n
}

func extendedKeyUsageName(identifier string) (string, bool) {
	switch identifier {
	case anyExtendedKeyUsageOID:
		return "any", true
	case oid.ServerAuth:
		return "serverAuth", true
	case oid.ClientAuth:
		return "clientAuth", true
	case oid.CodeSigning:
		return "codeSigning", true
	case oid.EmailProtection:
		return "emailProtection", true
	case oid.TimeStamping:
		return "timeStamping", true
	case oid.OCSPSigning:
		return "ocspSigning", true
	default:
		return "", false
	}
}
