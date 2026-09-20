package x509ext

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"net"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// GeneralName preserves one GeneralName exactly as encoded. RawDER includes
// the context-specific tag and length; RawValue is its contents octets.
type GeneralName struct {
	Tag      int
	RawDER   []byte
	RawValue []byte
}

func GeneralNameType(tag int) string {
	switch tag {
	case 0:
		return "otherName"
	case 1:
		return "rfc822Name"
	case 2:
		return "dNSName"
	case 3:
		return "x400Address"
	case 4:
		return "directoryName"
	case 5:
		return "ediPartyName"
	case 6:
		return "uniformResourceIdentifier"
	case 7:
		return "iPAddress"
	case 8:
		return "registeredID"
	default:
		return "unknown"
	}
}

// DecodeGeneralNames decodes exactly one non-empty GeneralNames SEQUENCE.
func DecodeGeneralNames(der []byte) ([]GeneralName, error) {
	input := cryptobyte.String(der)
	var names cryptobyte.String
	if !input.ReadASN1(&names, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("failed to read GeneralNames")
	}
	decoded, err := ReadGeneralNamesContents(&names)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("GeneralNames must not be empty")
	}
	return decoded, nil
}

// ReadGeneralNamesContents consumes consecutive GeneralName values from an
// implicit wrapper or a GeneralNames SEQUENCE body.
func ReadGeneralNamesContents(input *cryptobyte.String) ([]GeneralName, error) {
	var names []GeneralName
	for !input.Empty() {
		name, err := ReadGeneralName(input)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func ReadGeneralName(input *cryptobyte.String) (GeneralName, error) {
	return readGeneralNameWithIPLengths(input, 4, 16)
}

// ReadNameConstraintGeneralName decodes a GeneralName used as a subtree base,
// where iPAddress carries an address-and-mask pair.
func ReadNameConstraintGeneralName(input *cryptobyte.String) (GeneralName, error) {
	return readGeneralNameWithIPLengths(input, 8, 32)
}

func readGeneralNameWithIPLengths(input *cryptobyte.String, ipLengths ...int) (GeneralName, error) {
	var encoded cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !input.ReadAnyASN1Element(&encoded, &tag) {
		return GeneralName{}, fmt.Errorf("failed to read GeneralName")
	}

	element := encoded
	var content cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&content, &parsedTag) || !element.Empty() || parsedTag != tag {
		return GeneralName{}, fmt.Errorf("failed to decode GeneralName")
	}
	if err := validateGeneralName(tag, encoded, content, ipLengths...); err != nil {
		return GeneralName{}, err
	}
	return GeneralName{
		Tag:      int(tag) & 0x1f,
		RawDER:   append([]byte(nil), encoded...),
		RawValue: append([]byte(nil), content...),
	}, nil
}

func validateGeneralName(
	tag cryptobyte_asn1.Tag,
	encoded, content cryptobyte.String,
	ipLengths ...int,
) error {
	tagValue := int(tag)
	if tagValue&0xc0 != 0x80 || tagValue&0x1f > 8 {
		return fmt.Errorf("invalid GeneralName tag %d", tagValue)
	}
	if len(content) == 0 {
		return fmt.Errorf("GeneralName tag %d is empty", tagValue&0x1f)
	}

	tagNumber := tagValue & 0x1f
	constructed := tagValue&0x20 != 0
	wantConstructed := tagNumber == 0 || tagNumber == 3 || tagNumber == 4 || tagNumber == 5
	if constructed != wantConstructed {
		return fmt.Errorf("GeneralName tag %d has invalid primitive/constructed form", tagNumber)
	}

	switch tagNumber {
	case 0:
		if err := validateOtherName(content); err != nil {
			return fmt.Errorf("invalid otherName")
		}
	case 1, 2, 6:
		for _, octet := range content {
			if octet > 0x7f {
				return fmt.Errorf("GeneralName tag %d contains a non-IA5 octet", tagNumber)
			}
		}
	case 3:
		value := content
		var builtIn cryptobyte.String
		if !value.ReadASN1(&builtIn, cryptobyte_asn1.SEQUENCE) || (builtIn.Empty() && value.Empty()) {
			return fmt.Errorf("invalid x400Address")
		}
	case 4:
		parsed, err := internalasn1.ParseDistinguishedNameStrict(content)
		if err != nil || len(parsed.RDNs) == 0 {
			return fmt.Errorf("invalid directoryName")
		}
	case 5:
		if err := validateEDIPartyName(content); err != nil {
			return fmt.Errorf("invalid ediPartyName")
		}
	case 7:
		validLength := false
		for _, length := range ipLengths {
			if len(content) == length {
				validLength = true
				break
			}
		}
		if !validLength {
			return fmt.Errorf("invalid iPAddress length %d", len(content))
		}
		if len(content) == 8 || len(content) == 32 {
			half := len(content) / 2
			if _, bits := net.IPMask(content[half:]).Size(); bits == 0 {
				return fmt.Errorf("invalid iPAddress constraint mask")
			}
		}
	case 8:
		if _, err := DecodeRegisteredID(encoded); err != nil {
			return fmt.Errorf("invalid registeredID")
		}
	}
	return nil
}

func validateOtherName(content []byte) error {
	value := cryptobyte.String(content)
	var typeID stdasn1.ObjectIdentifier
	var otherValue cryptobyte.String
	if !value.ReadASN1ObjectIdentifier(&typeID) ||
		!value.ReadASN1(&otherValue, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!value.Empty() || otherValue.Empty() {
		return fmt.Errorf("invalid otherName")
	}
	inner := otherValue
	var innerDER cryptobyte.String
	var innerTag cryptobyte_asn1.Tag
	if !inner.ReadAnyASN1Element(&innerDER, &innerTag) || !inner.Empty() {
		return fmt.Errorf("otherName value must contain exactly one DER element")
	}
	return nil
}

func validateEDIPartyName(content []byte) error {
	value := cryptobyte.String(content)
	if value.PeekASN1Tag(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		if err := readExplicitDirectoryString(
			&value,
			cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(),
		); err != nil {
			return err
		}
	}
	if !value.PeekASN1Tag(cryptobyte_asn1.Tag(1).Constructed().ContextSpecific()) {
		return fmt.Errorf("missing partyName")
	}
	if err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(1).Constructed().ContextSpecific(),
	); err != nil {
		return err
	}
	if !value.Empty() {
		return fmt.Errorf("unexpected ediPartyName data")
	}
	return nil
}

func readExplicitDirectoryString(input *cryptobyte.String, tag cryptobyte_asn1.Tag) error {
	var explicit cryptobyte.String
	if !input.ReadASN1(&explicit, tag) {
		return fmt.Errorf("invalid explicit DirectoryString")
	}
	var element cryptobyte.String
	var stringTag cryptobyte_asn1.Tag
	if !explicit.ReadAnyASN1Element(&element, &stringTag) || !explicit.Empty() {
		return fmt.Errorf("invalid DirectoryString")
	}
	encoded := element
	var rawValue cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !encoded.ReadAnyASN1(&rawValue, &parsedTag) || !encoded.Empty() || parsedTag != stringTag {
		return fmt.Errorf("invalid DirectoryString")
	}
	if _, err := internalasn1.DecodeDirectoryString(int(stringTag), rawValue); err != nil {
		return fmt.Errorf("invalid DirectoryString: %w", err)
	}
	return nil
}

func DecodeRegisteredID(encoded []byte) (string, error) {
	oidDER := append([]byte(nil), encoded...)
	if len(oidDER) == 0 {
		return "", fmt.Errorf("invalid registeredID")
	}
	oidDER[0] = byte(cryptobyte_asn1.OBJECT_IDENTIFIER)
	var identifier stdasn1.ObjectIdentifier
	rest, err := stdasn1.Unmarshal(oidDER, &identifier)
	if err != nil || len(rest) != 0 || len(identifier) == 0 {
		return "", fmt.Errorf("invalid registeredID")
	}
	return identifier.String(), nil
}

// IPString returns the conventional text form for an iPAddress GeneralName.
func (n GeneralName) IPString() string {
	if n.Tag != 7 {
		return ""
	}
	return net.IP(n.RawValue).String()
}
