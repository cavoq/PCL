package x509ext

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/x509asn1"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// GeneralName preserves one GeneralName exactly as encoded. RawDER includes
// the context-specific tag and length; RawValue is its contents octets.
// OtherName and EDIPartyName hold the decoded structure of those forms.
type GeneralName struct {
	Tag          int
	RawDER       []byte
	RawValue     []byte
	OtherName    *OtherName
	EDIPartyName *EDIPartyName
}

// OtherName is a decoded otherName: the type identifier and the DER of the
// value inside its explicit [0] tag.
type OtherName struct {
	TypeID string
	Value  []byte
}

// DirectoryString is a decoded DirectoryString with the ASN.1 string type
// and encoding it had.
type DirectoryString struct {
	Tag      int
	RawDER   []byte
	RawValue []byte
	Value    string
}

// EDIPartyName is a decoded ediPartyName.
type EDIPartyName struct {
	NameAssigner *DirectoryString
	PartyName    DirectoryString
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
	name, err := readGeneralNameWithIPLengths(input, 8, 32)
	if err != nil {
		return GeneralName{}, err
	}
	if name.Tag == 2 && !ValidDNSNameConstraint(string(name.RawValue)) {
		return GeneralName{}, fmt.Errorf("dNSName constraint %q is not in the preferred name syntax", name.RawValue)
	}
	return name, nil
}

// ValidDNSNameConstraint reports whether a dNSName subtree is empty, which
// covers every name, or a domain name in the preferred name syntax (RFC 5280
// 4.2.1.10). Unlike URI and rfc822Name constraints, a dNSName constraint has
// no leading-period form: "host.example.com" already covers every name
// below it.
func ValidDNSNameConstraint(constraint string) bool {
	return constraint == "" || PreferredNameSyntax(constraint)
}

// PreferredNameSyntax reports whether name is a domain name in the preferred
// name syntax of RFC 1034 3.5 as modified by RFC 1123 2.1: dot-separated
// labels of letters, digits and interior hyphens, each at most 63 octets,
// at most 253 octets in total and without a trailing dot.
func PreferredNameSyntax(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
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
	name := GeneralName{
		Tag:      int(tag) & 0x1f,
		RawDER:   append([]byte(nil), encoded...),
		RawValue: append([]byte(nil), content...),
	}
	if err := decodeGeneralNameContent(&name, tag, encoded, content, ipLengths...); err != nil {
		return GeneralName{}, err
	}
	return name, nil
}

// decodeGeneralNameContent validates the contents of name's form and sets
// the decoded structure of otherName and ediPartyName.
func decodeGeneralNameContent(
	name *GeneralName,
	tag cryptobyte_asn1.Tag,
	encoded, content cryptobyte.String,
	ipLengths ...int,
) error {
	tagNumber, err := validateGeneralNameForm(tag, content)
	if err != nil {
		return err
	}

	switch tagNumber {
	case 0:
		otherName, err := decodeOtherName(content)
		if err != nil {
			return fmt.Errorf("invalid otherName")
		}
		name.OtherName = &otherName
	case 1, 2, 6:
		return validateIA5Octets(tagNumber, content)
	case 3:
		return validateX400Address(content)
	case 4:
		parsed, err := x509asn1.ParseDistinguishedNameStrict(content)
		if err != nil || len(parsed.RDNs) == 0 {
			return fmt.Errorf("invalid directoryName")
		}
	case 5:
		party, err := decodeEDIPartyName(content)
		if err != nil {
			return fmt.Errorf("invalid ediPartyName")
		}
		name.EDIPartyName = &party
	case 7:
		return validateIPAddressName(content, ipLengths)
	case 8:
		if _, err := DecodeRegisteredID(encoded); err != nil {
			return fmt.Errorf("invalid registeredID")
		}
	}
	return nil
}

// validateGeneralNameForm checks the context-specific tag number, non-empty
// content and the primitive or constructed form each alternative requires,
// and returns the tag number.
func validateGeneralNameForm(tag cryptobyte_asn1.Tag, content cryptobyte.String) (int, error) {
	tagValue := int(tag)
	if tagValue&0xc0 != 0x80 || tagValue&0x1f > 8 {
		return 0, fmt.Errorf("invalid GeneralName tag %d", tagValue)
	}
	tagNumber := tagValue & 0x1f
	if len(content) == 0 {
		return 0, fmt.Errorf("GeneralName tag %d is empty", tagNumber)
	}

	constructed := tagValue&0x20 != 0
	wantConstructed := tagNumber == 0 || tagNumber == 3 || tagNumber == 4 || tagNumber == 5
	if constructed != wantConstructed {
		return 0, fmt.Errorf("GeneralName tag %d has invalid primitive/constructed form", tagNumber)
	}
	return tagNumber, nil
}

func validateIA5Octets(tagNumber int, content []byte) error {
	for _, octet := range content {
		if octet > 0x7f {
			return fmt.Errorf("GeneralName tag %d contains a non-IA5 octet", tagNumber)
		}
	}
	return nil
}

func validateX400Address(content cryptobyte.String) error {
	var builtIn cryptobyte.String
	if !content.ReadASN1(&builtIn, cryptobyte_asn1.SEQUENCE) || (builtIn.Empty() && content.Empty()) {
		return fmt.Errorf("invalid x400Address")
	}
	return nil
}

// validateIPAddressName checks the iPAddress length against the lengths
// allowed in this context; address-and-mask pairs need a contiguous mask.
func validateIPAddressName(content []byte, ipLengths []int) error {
	if !slices.Contains(ipLengths, len(content)) {
		return fmt.Errorf("invalid iPAddress length %d", len(content))
	}
	if len(content) == 8 || len(content) == 32 {
		half := len(content) / 2
		if _, bits := net.IPMask(content[half:]).Size(); bits == 0 {
			return fmt.Errorf("invalid iPAddress constraint mask")
		}
	}
	return nil
}

func decodeOtherName(content []byte) (OtherName, error) {
	value := cryptobyte.String(content)
	var typeID stdasn1.ObjectIdentifier
	var otherValue cryptobyte.String
	if !value.ReadASN1ObjectIdentifier(&typeID) ||
		!value.ReadASN1(&otherValue, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!value.Empty() || otherValue.Empty() {
		return OtherName{}, fmt.Errorf("invalid otherName")
	}
	inner := otherValue
	var innerDER cryptobyte.String
	var innerTag cryptobyte_asn1.Tag
	if !inner.ReadAnyASN1Element(&innerDER, &innerTag) || !inner.Empty() {
		return OtherName{}, fmt.Errorf("otherName value must contain exactly one DER element")
	}
	return OtherName{TypeID: typeID.String(), Value: append([]byte(nil), otherValue...)}, nil
}

func decodeEDIPartyName(content []byte) (EDIPartyName, error) {
	value := cryptobyte.String(content)
	nameAssigner, present, err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(),
		"nameAssigner",
		false,
	)
	if err != nil {
		return EDIPartyName{}, err
	}
	partyName, _, err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(1).Constructed().ContextSpecific(),
		"partyName",
		true,
	)
	if err != nil {
		return EDIPartyName{}, err
	}
	if !value.Empty() {
		return EDIPartyName{}, fmt.Errorf("unexpected ediPartyName data")
	}

	decoded := EDIPartyName{PartyName: partyName}
	if present {
		decoded.NameAssigner = &nameAssigner
	}
	return decoded, nil
}

func readExplicitDirectoryString(
	input *cryptobyte.String,
	tag cryptobyte_asn1.Tag,
	field string,
	required bool,
) (DirectoryString, bool, error) {
	if !input.PeekASN1Tag(tag) {
		if required {
			return DirectoryString{}, false, fmt.Errorf("missing %s", field)
		}
		return DirectoryString{}, false, nil
	}

	var explicit cryptobyte.String
	if !input.ReadASN1(&explicit, tag) {
		return DirectoryString{}, false, fmt.Errorf("invalid %s", field)
	}

	var rawDER cryptobyte.String
	var stringTag cryptobyte_asn1.Tag
	if !explicit.ReadAnyASN1Element(&rawDER, &stringTag) || !explicit.Empty() {
		return DirectoryString{}, false, fmt.Errorf("invalid %s DirectoryString", field)
	}
	element := rawDER
	var rawValue cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&rawValue, &parsedTag) || !element.Empty() || parsedTag != stringTag {
		return DirectoryString{}, false, fmt.Errorf("invalid %s DirectoryString", field)
	}
	decoded, err := x509asn1.DecodeDirectoryString(int(stringTag), rawValue)
	if err != nil {
		return DirectoryString{}, false, fmt.Errorf("invalid %s: %w", field, err)
	}
	return DirectoryString{
		Tag:      int(stringTag),
		RawDER:   append([]byte(nil), rawDER...),
		RawValue: append([]byte(nil), rawValue...),
		Value:    decoded,
	}, true, nil
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
