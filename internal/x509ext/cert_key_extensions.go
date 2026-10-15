package x509ext

import (
	stdasn1 "encoding/asn1"
	"fmt"

	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const AnyExtendedKeyUsageOID = "2.5.29.37.0"

// KeyUsage is a decoded Key Usage extension: the asserted bits as a value
// with bit 0 (digitalSignature) as its least significant bit.
type KeyUsage struct {
	Value      int
	BitLength  int
	UnusedBits int
	RawDER     []byte
	RawValue   []byte
}

// DecodeKeyUsage decodes exactly one RFC 5280 KeyUsage BIT STRING. Bits
// beyond decipherOnly and non-canonical trailing zero bits are errors.
func DecodeKeyUsage(extValue []byte) (KeyUsage, error) {
	input := cryptobyte.String(extValue)
	var bits stdasn1.BitString
	if !input.ReadASN1BitString(&bits) || !input.Empty() {
		return KeyUsage{}, fmt.Errorf("invalid KeyUsage BIT STRING")
	}
	if bits.BitLength > 9 {
		return KeyUsage{}, fmt.Errorf("KeyUsage contains undefined bit %d", bits.BitLength-1)
	}
	// A DER encoding of a named bit list omits trailing zero bits. The empty
	// list remains structurally representable so profile policy can report the
	// RFC requirement that at least one bit be asserted.
	if bits.BitLength > 0 && bits.At(bits.BitLength-1) == 0 {
		return KeyUsage{}, fmt.Errorf("KeyUsage has non-canonical trailing zero bits")
	}

	value := 0
	for bit := 0; bit < bits.BitLength; bit++ {
		if bits.At(bit) != 0 {
			value |= 1 << bit
		}
	}
	return KeyUsage{
		Value:      value,
		BitLength:  bits.BitLength,
		UnusedBits: len(bits.Bytes)*8 - bits.BitLength,
		RawDER:     append([]byte(nil), extValue...),
		RawValue:   append([]byte(nil), bits.Bytes...),
	}, nil
}

// BasicConstraints is a decoded Basic Constraints extension that records
// whether its DEFAULT and OPTIONAL fields were encoded.
type BasicConstraints struct {
	CA                       bool
	CAPresent                bool
	PathLenConstraint        NonNegativeInteger
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

// DecodeBasicConstraintsStrict exposes strictly decoded presence and counter
// facts without relying on the underlying x509 library's native int fields.
func DecodeBasicConstraintsStrict(extValue []byte) (BasicConstraintsFacts, error) {
	decoded, err := DecodeBasicConstraints(extValue)
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

// DecodeBasicConstraints decodes exactly one BasicConstraints sequence. An
// explicitly encoded DEFAULT cA false is an error.
func DecodeBasicConstraints(extValue []byte) (BasicConstraints, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return BasicConstraints{}, fmt.Errorf("invalid BasicConstraints sequence")
	}

	decoded := BasicConstraints{RawDER: append([]byte(nil), extValue...)}
	if sequence.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !sequence.ReadASN1Boolean(&decoded.CA) {
			return BasicConstraints{}, fmt.Errorf("invalid BasicConstraints cA boolean")
		}
		if !decoded.CA {
			return BasicConstraints{}, fmt.Errorf(
				"BasicConstraints explicitly encodes DEFAULT cA false",
			)
		}
		decoded.CAPresent = true
	}
	if sequence.PeekASN1Tag(cryptobyte_asn1.INTEGER) {
		var encoded cryptobyte.String
		if !sequence.ReadASN1Element(&encoded, cryptobyte_asn1.INTEGER) {
			return BasicConstraints{}, fmt.Errorf("invalid pathLenConstraint")
		}
		value, err := DecodeNonNegativeInteger(encoded)
		if err != nil {
			return BasicConstraints{}, fmt.Errorf("invalid pathLenConstraint: %w", err)
		}
		decoded.PathLenConstraint = value
		decoded.PathLenConstraintPresent = true
	}
	if !sequence.Empty() {
		return BasicConstraints{}, fmt.Errorf("unexpected BasicConstraints field")
	}
	return decoded, nil
}

// ExtendedKeyUsage is a decoded Extended Key Usage extension with every
// KeyPurposeId in encoding order.
type ExtendedKeyUsage struct {
	Usages []KeyPurpose
	RawDER []byte
}

// KeyPurpose is one KeyPurposeId of an Extended Key Usage extension.
type KeyPurpose struct {
	OID    string
	RawDER []byte
}

// DecodeExtendedKeyUsageOIDsStrict returns every KeyPurposeId in wire order.
// Reading the identifiers from the extension DER avoids losing usages that the
// underlying x509 library recognizes but PCL does not assign a friendly name.
func DecodeExtendedKeyUsageOIDsStrict(extValue []byte) ([]string, error) {
	decoded, err := DecodeExtendedKeyUsage(extValue)
	if err != nil {
		return nil, err
	}

	identifiers := make([]string, len(decoded.Usages))
	for index, usage := range decoded.Usages {
		identifiers[index] = usage.OID
	}
	return identifiers, nil
}

// DecodeExtendedKeyUsage decodes an Extended Key Usage extension value,
// including identifiers unknown to the x509 library. It must not be empty.
func DecodeExtendedKeyUsage(extValue []byte) (ExtendedKeyUsage, error) {
	input := cryptobyte.String(extValue)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return ExtendedKeyUsage{}, fmt.Errorf("invalid ExtKeyUsageSyntax sequence")
	}
	if sequence.Empty() {
		return ExtendedKeyUsage{}, fmt.Errorf("ExtKeyUsageSyntax must not be empty")
	}

	decoded := ExtendedKeyUsage{RawDER: append([]byte(nil), extValue...)}
	for index := 0; !sequence.Empty(); index++ {
		var encoded cryptobyte.String
		if !sequence.ReadASN1Element(&encoded, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			return ExtendedKeyUsage{}, fmt.Errorf("invalid KeyPurposeId %d", index)
		}
		value := encoded
		var identifier stdasn1.ObjectIdentifier
		if !value.ReadASN1ObjectIdentifier(&identifier) || !value.Empty() {
			return ExtendedKeyUsage{}, fmt.Errorf("invalid KeyPurposeId %d", index)
		}
		decoded.Usages = append(decoded.Usages, KeyPurpose{
			OID:    identifier.String(),
			RawDER: append([]byte(nil), encoded...),
		})
	}
	return decoded, nil
}

// ExtendedKeyUsageName returns PCL's friendly name for a well-known
// KeyPurposeId, such as serverAuth.
func ExtendedKeyUsageName(identifier string) (string, bool) {
	switch identifier {
	case AnyExtendedKeyUsageOID:
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
