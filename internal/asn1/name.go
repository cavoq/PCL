package asn1

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// DistinguishedName is a lossless representation of an X.501 Name. RDNs and
// their attributes remain in their encoded order; no OID-specific policy or
// normalization is applied.
type DistinguishedName struct {
	RawDER []byte
	RDNs   []RelativeDistinguishedName
}

// RelativeDistinguishedName represents one non-empty SET OF
// AttributeTypeAndValue values.
type RelativeDistinguishedName struct {
	RawDER     []byte
	Attributes []NameAttribute
}

// NameAttribute represents one AttributeTypeAndValue. RawDER contains the
// complete AttributeTypeAndValue SEQUENCE, while RawValue contains only the
// contents of its value element.
type NameAttribute struct {
	OID      string
	Tag      int
	Encoding string
	RawDER   []byte
	RawValue []byte
	Value    string
}

// ParseDistinguishedNameStrict parses exactly one DER-encoded X.501 Name. It
// preserves the encoded RDN and attribute ordering and owns all returned byte
// slices independently of the input.
func ParseDistinguishedNameStrict(der []byte) (DistinguishedName, error) {
	result := DistinguishedName{RawDER: cloneNameBytes(der)}
	input := cryptobyte.String(der)

	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return result, fmt.Errorf("invalid distinguished name sequence")
	}

	rdnIndex := 0
	for !sequence.Empty() {
		var rdnDER cryptobyte.String
		if !sequence.ReadASN1Element(&rdnDER, cryptobyte_asn1.SET) {
			return result, fmt.Errorf("invalid relative distinguished name %d", rdnIndex)
		}

		rdn, err := parseRelativeDistinguishedName(rdnDER, rdnIndex)
		if err != nil {
			return result, err
		}
		result.RDNs = append(result.RDNs, rdn)
		rdnIndex++
	}

	return result, nil
}

func parseRelativeDistinguishedName(der cryptobyte.String, rdnIndex int) (RelativeDistinguishedName, error) {
	result := RelativeDistinguishedName{RawDER: cloneNameBytes(der)}
	input := cryptobyte.String(der)

	var attributes cryptobyte.String
	if !input.ReadASN1(&attributes, cryptobyte_asn1.SET) || !input.Empty() {
		return result, fmt.Errorf("invalid relative distinguished name %d", rdnIndex)
	}
	if attributes.Empty() {
		return result, fmt.Errorf("relative distinguished name %d must not be empty", rdnIndex)
	}

	attributeIndex := 0
	var previousAttributeDER cryptobyte.String
	for !attributes.Empty() {
		var attributeDER cryptobyte.String
		if !attributes.ReadASN1Element(&attributeDER, cryptobyte_asn1.SEQUENCE) {
			return result, fmt.Errorf("invalid attribute %d in relative distinguished name %d", attributeIndex, rdnIndex)
		}
		if previousAttributeDER != nil && bytes.Compare(previousAttributeDER, attributeDER) > 0 {
			return result, fmt.Errorf("attributes in relative distinguished name %d are not in DER SET order", rdnIndex)
		}

		attribute, err := parseNameAttribute(attributeDER, rdnIndex, attributeIndex)
		if err != nil {
			return result, err
		}
		result.Attributes = append(result.Attributes, attribute)
		previousAttributeDER = attributeDER
		attributeIndex++
	}

	return result, nil
}

func parseNameAttribute(der cryptobyte.String, rdnIndex, attributeIndex int) (NameAttribute, error) {
	result := NameAttribute{RawDER: cloneNameBytes(der)}
	input := cryptobyte.String(der)

	var attribute cryptobyte.String
	if !input.ReadASN1(&attribute, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return result, fmt.Errorf("invalid attribute %d in relative distinguished name %d", attributeIndex, rdnIndex)
	}

	var oid stdasn1.ObjectIdentifier
	if !attribute.ReadASN1ObjectIdentifier(&oid) {
		return result, fmt.Errorf("invalid attribute OID at index %d in relative distinguished name %d", attributeIndex, rdnIndex)
	}
	result.OID = oid.String()

	var valueDER cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !attribute.ReadAnyASN1Element(&valueDER, &tag) {
		return result, fmt.Errorf("missing attribute value at index %d in relative distinguished name %d", attributeIndex, rdnIndex)
	}
	if !attribute.Empty() {
		return result, fmt.Errorf("trailing fields in attribute %d of relative distinguished name %d", attributeIndex, rdnIndex)
	}

	valueInput := cryptobyte.String(valueDER)
	var value cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !valueInput.ReadAnyASN1(&value, &parsedTag) || !valueInput.Empty() || parsedTag != tag {
		return result, fmt.Errorf("invalid attribute value at index %d in relative distinguished name %d", attributeIndex, rdnIndex)
	}

	result.Tag = int(tag)
	if encoding := constructedNameStringEncoding(result.Tag); encoding != EncodingUnknown {
		return result, fmt.Errorf(
			"attribute value at index %d in relative distinguished name %d uses constructed %s encoding",
			attributeIndex,
			rdnIndex,
			StringTypeName(result.Tag&0x1f),
		)
	}
	result.Encoding = StringTypeName(result.Tag)
	result.RawValue = cloneNameBytes(value)

	decoded, err := decodeNameString(GetEncodingType(result.Tag), value)
	if err != nil {
		return result, fmt.Errorf("invalid %s attribute value at index %d in relative distinguished name %d: %w", result.Encoding, attributeIndex, rdnIndex, err)
	}
	result.Value = decoded
	return result, nil
}

func constructedNameStringEncoding(tag int) EncodingType {
	const (
		classMask        = 0xc0
		constructedBit   = 0x20
		lowTagNumberMask = 0x1f
	)
	if tag&classMask != 0 || tag&constructedBit == 0 {
		return EncodingUnknown
	}
	return GetEncodingType(tag & lowTagNumberMask)
}

func decodeNameString(encoding EncodingType, value []byte) (string, error) {
	switch encoding {
	case EncodingUTF8String:
		if !utf8.Valid(value) {
			return "", fmt.Errorf("invalid UTF-8")
		}
		return string(value), nil
	case EncodingPrintableString:
		for _, character := range value {
			if !isPrintableStringChar(character) {
				return "", fmt.Errorf("invalid PrintableString character 0x%02x", character)
			}
		}
		return string(value), nil
	case EncodingIA5String:
		for _, character := range value {
			if character > 0x7f {
				return "", fmt.Errorf("invalid IA5String character 0x%02x", character)
			}
		}
		return string(value), nil
	case EncodingVisibleString:
		for _, character := range value {
			if character < 0x20 || character > 0x7e {
				return "", fmt.Errorf("invalid VisibleString character 0x%02x", character)
			}
		}
		return string(value), nil
	case EncodingBMPString:
		return decodeBMPString(value)
	case EncodingUniversalString:
		return decodeUniversalString(value)
	case EncodingTeletexString:
		// Treat T.61 as Latin-1, matching encoding/asn1 and BoringSSL. T.61 is
		// close to, but not precisely, Latin-1; RawValue retains the wire bytes.
		decoded := make([]byte, 0, len(value))
		for _, character := range value {
			decoded = utf8.AppendRune(decoded, rune(character))
		}
		return string(decoded), nil
	case EncodingUnknown:
		return "", nil
	default:
		return "", nil
	}
}

func decodeBMPString(value []byte) (string, error) {
	if len(value)%2 != 0 {
		return "", fmt.Errorf("BMPString length is not divisible by two")
	}

	var decoded strings.Builder
	for offset := 0; offset < len(value); offset += 2 {
		codePoint := binary.BigEndian.Uint16(value[offset : offset+2])
		character := rune(codePoint)
		if isSurrogate(character) || isBMPNoncharacter(codePoint) {
			return "", fmt.Errorf("BMPString contains invalid code point U+%04X", codePoint)
		}
		decoded.WriteRune(character)
	}
	return decoded.String(), nil
}

func decodeUniversalString(value []byte) (string, error) {
	if len(value)%4 != 0 {
		return "", fmt.Errorf("UniversalString length is not divisible by four")
	}

	var decoded strings.Builder
	for offset := 0; offset < len(value); offset += 4 {
		codePoint := binary.BigEndian.Uint32(value[offset : offset+4])
		if codePoint > uint32(utf8.MaxRune) || isSurrogate(rune(codePoint)) {
			return "", fmt.Errorf("UniversalString contains invalid code point U+%08X", codePoint)
		}
		character := rune(codePoint)
		decoded.WriteRune(character)
	}
	return decoded.String(), nil
}

func isSurrogate(character rune) bool {
	return character >= 0xd800 && character <= 0xdfff
}

func isBMPNoncharacter(codePoint uint16) bool {
	return codePoint == 0xfffe || codePoint == 0xffff ||
		(codePoint >= 0xfdd0 && codePoint <= 0xfdef)
}

func cloneNameBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
