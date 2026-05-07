package asn1

type EncodingType int

const (
	EncodingUnknown EncodingType = iota
	EncodingIA5String
	EncodingPrintableString
	EncodingUTF8String
	EncodingBMPString
	EncodingUniversalString
)

type EncodingInfo struct {
	Type         EncodingType
	TagName      string
	RawBytes     []byte
	StringValue  string
	ValidChars   bool   // whether all characters are valid for the encoding type
	InvalidChars []byte // characters that violate encoding rules
}

// ValidateIA5String validates that a byte sequence conforms to IA5String encoding.
// IA5String is equivalent to ASCII (0x00-0x7F).
func ValidateIA5String(derBytes []byte) (*EncodingInfo, error) {
	info := newEncodingInfo(EncodingIA5String, "IA5String", derBytes)
	valueBytes, err := readDERValue(derBytes, 22, "IA5String")
	if err != nil {
		return nil, err
	}
	info.StringValue = string(valueBytes)

	for _, b := range valueBytes {
		if b > 0x7F {
			info.ValidChars = false
			info.InvalidChars = append(info.InvalidChars, b)
		}
	}

	return info, nil
}

// ValidatePrintableString validates that a byte sequence conforms to PrintableString encoding.
// PrintableString allows: A-Z, a-z, 0-9, space, '(),./:=?- and special chars
// Per RFC 5280 Appendix A.1: PrintableString character set
func ValidatePrintableString(derBytes []byte) (*EncodingInfo, error) {
	info := newEncodingInfo(EncodingPrintableString, "PrintableString", derBytes)
	valueBytes, err := readDERValue(derBytes, 19, "PrintableString")
	if err != nil {
		return nil, err
	}
	info.StringValue = string(valueBytes)

	for _, b := range valueBytes {
		if !isPrintableStringChar(b) {
			info.ValidChars = false
			info.InvalidChars = append(info.InvalidChars, b)
		}
	}

	return info, nil
}

func newEncodingInfo(encodingType EncodingType, tagName string, derBytes []byte) *EncodingInfo {
	return &EncodingInfo{
		Type:       encodingType,
		TagName:    tagName,
		RawBytes:   derBytes,
		ValidChars: true,
	}
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
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?', '&', '[', ']', '#', '@', '!', '"', '%', '*', ';', '<', '>', '_', '\\', '{', '}', '|', '~', '^':
		return true
	}
	return false
}

// GetEncodingType returns the encoding type from ASN.1 tag.
func GetEncodingType(tag int) EncodingType {
	switch tag {
	case 22:
		return EncodingIA5String
	case 19:
		return EncodingPrintableString
	case 12:
		return EncodingUTF8String
	case 30:
		return EncodingBMPString
	case 28:
		return EncodingUniversalString
	default:
		return EncodingUnknown
	}
}
