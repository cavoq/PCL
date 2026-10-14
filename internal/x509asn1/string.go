package x509asn1

import "fmt"

type EncodingType int

const (
	EncodingUnknown EncodingType = iota
	EncodingIA5String
	EncodingPrintableString
	EncodingUTF8String
	EncodingBMPString
	EncodingUniversalString
	EncodingVisibleString
	EncodingTeletexString
)

type stringTypeDescriptor struct {
	encoding EncodingType
	name     string
}

var stringTypesByTag = map[int]stringTypeDescriptor{
	12: {encoding: EncodingUTF8String, name: "utf8String"},
	19: {encoding: EncodingPrintableString, name: "printableString"},
	20: {encoding: EncodingTeletexString, name: "teletexString"},
	22: {encoding: EncodingIA5String, name: "ia5String"},
	26: {encoding: EncodingVisibleString, name: "visibleString"},
	28: {encoding: EncodingUniversalString, name: "universalString"},
	30: {encoding: EncodingBMPString, name: "bmpString"},
}

// IsPrintableString reports whether every character of s is in the ASN.1
// PrintableString alphabet (RFC 5280 Appendix A.1).
func IsPrintableString(s string) bool {
	for index := 0; index < len(s); index++ {
		if !isPrintableStringChar(s[index]) {
			return false
		}
	}
	return true
}

// IsIA5String reports whether s contains only IA5 (7-bit ASCII) characters.
func IsIA5String(s string) bool {
	for index := 0; index < len(s); index++ {
		if s[index] > 0x7f {
			return false
		}
	}
	return true
}

func isPrintableStringChar(b byte) bool {
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
		return true
	}
	return false
}

// GetEncodingType returns the encoding type from ASN.1 tag.
func GetEncodingType(tag int) EncodingType {
	if descriptor, ok := stringTypesByTag[tag]; ok {
		return descriptor.encoding
	}
	return EncodingUnknown
}

// StringTypeName returns the canonical policy-facing name for an ASN.1
// character string tag.
func StringTypeName(tag int) string {
	if descriptor, ok := stringTypesByTag[tag]; ok {
		return descriptor.name
	}
	return "unknown"
}

// DecodeDirectoryString decodes one primitive DirectoryString value. The
// caller owns the surrounding ASN.1 element and supplies its universal tag and
// content octets.
func DecodeDirectoryString(tag int, value []byte) (string, error) {
	if len(value) == 0 {
		return "", fmt.Errorf("DirectoryString must not be empty")
	}

	encoding := GetEncodingType(tag)
	switch encoding {
	case EncodingUTF8String,
		EncodingPrintableString,
		EncodingTeletexString,
		EncodingUniversalString,
		EncodingBMPString:
		return decodeNameString(encoding, value)
	default:
		return "", fmt.Errorf("unsupported DirectoryString tag %d", tag)
	}
}
