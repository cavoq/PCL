package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// generalNamesInfo contains certificate GeneralNames facts that zcrypto does
// not expose through typed certificate fields.
type generalNamesInfo struct {
	Count         int
	X400Addresses [][]byte
}

type parsedGeneralName struct {
	Tag     int
	Encoded []byte
	Content []byte
}

func generalNameType(tag int) string {
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

func readGeneralName(input *cryptobyte.String) (parsedGeneralName, error) {
	var encoded cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !input.ReadAnyASN1Element(&encoded, &tag) {
		return parsedGeneralName{}, fmt.Errorf("failed to read GeneralName")
	}
	if err := validateGeneralName(tag, encoded); err != nil {
		return parsedGeneralName{}, err
	}

	element := cryptobyte.String(encoded)
	var content cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&content, &parsedTag) || !element.Empty() || parsedTag != tag {
		return parsedGeneralName{}, fmt.Errorf("failed to decode GeneralName")
	}

	return parsedGeneralName{
		Tag:     int(tag) & 0x1f,
		Encoded: append([]byte(nil), encoded...),
		Content: append([]byte(nil), content...),
	}, nil
}

// readGeneralNames consumes consecutive GeneralName values from input. The
// surrounding SEQUENCE or implicit context-specific wrapper is owned by the
// caller because GeneralNames appears under several different schemas.
func readGeneralNames(input *cryptobyte.String) ([]parsedGeneralName, error) {
	var names []parsedGeneralName
	for !input.Empty() {
		name, err := readGeneralName(input)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func buildParsedGeneralName(name string, value parsedGeneralName) *node.Node {
	n := node.New(name, nil)
	n.Children["type"] = node.New("type", generalNameType(value.Tag))
	n.Children["tag"] = node.New("tag", value.Tag)

	switch value.Tag {
	case 1, 2, 6:
		text := string(value.Content)
		n.Children["value"] = node.New("value", text)
		if value.Tag == 6 {
			if scheme, _, ok := strings.Cut(text, ":"); ok {
				n.Children["scheme"] = node.New("scheme", scheme)
			}
		}
	default:
		n.Children["value"] = node.New("value", value.Content)
	}

	return n
}

func addParsedGeneralNames(target *node.Node, names []parsedGeneralName) {
	for index, name := range names {
		key := fmt.Sprintf("%d", index)
		target.Children[key] = buildParsedGeneralName(key, name)
	}
}

func parseGeneralNamesInfo(value []byte) (generalNamesInfo, error) {
	input := cryptobyte.String(value)
	var names cryptobyte.String
	if !input.ReadASN1(&names, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return generalNamesInfo{}, fmt.Errorf("failed to read GeneralNames")
	}

	parsedNames, err := readGeneralNames(&names)
	if err != nil {
		return generalNamesInfo{}, err
	}

	info := generalNamesInfo{Count: len(parsedNames)}
	for _, name := range parsedNames {
		if name.Tag == 3 {
			info.X400Addresses = append(info.X400Addresses, name.Encoded)
		}
	}

	return info, nil
}

func validateGeneralName(tag cryptobyte_asn1.Tag, encoded cryptobyte.String) error {
	tagValue := int(tag)
	if tagValue&0xc0 != 0x80 || tagValue&0x1f > 8 {
		return fmt.Errorf("invalid GeneralName tag %d", tagValue)
	}

	element := cryptobyte.String(encoded)
	var content cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&content, &parsedTag) || !element.Empty() || parsedTag != tag {
		return fmt.Errorf("failed to parse GeneralName tag %d", tagValue&0x1f)
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
	case 0: // otherName: implicit SEQUENCE content (OID, [0] EXPLICIT value)
		value := cryptobyte.String(content)
		var typeID cryptobyte.String
		var otherValue cryptobyte.String
		if !value.ReadASN1(&typeID, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
			!value.ReadASN1(&otherValue, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
			!value.Empty() || len(otherValue) == 0 {
			return fmt.Errorf("invalid otherName")
		}
	case 3: // x400Address: implicit ORAddress, whose first component is a SEQUENCE
		value := cryptobyte.String(content)
		var builtIn cryptobyte.String
		if !value.ReadASN1(&builtIn, cryptobyte_asn1.SEQUENCE) || (builtIn.Empty() && value.Empty()) {
			return fmt.Errorf("invalid x400Address")
		}
	case 4: // directoryName: explicit Name/RDNSequence
		value := cryptobyte.String(content)
		var rdnSequence cryptobyte.String
		if !value.ReadASN1(&rdnSequence, cryptobyte_asn1.SEQUENCE) || !value.Empty() || rdnSequence.Empty() {
			return fmt.Errorf("invalid directoryName")
		}
	case 5: // ediPartyName: partyName [1] is required
		value := cryptobyte.String(content)
		value.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific())
		var partyName cryptobyte.String
		if !value.ReadASN1(&partyName, cryptobyte_asn1.Tag(1).Constructed().ContextSpecific()) ||
			!value.Empty() || partyName.Empty() {
			return fmt.Errorf("invalid ediPartyName")
		}
	case 7:
		if len(content) != 4 && len(content) != 16 {
			return fmt.Errorf("invalid iPAddress length %d", len(content))
		}
	case 8:
		oidDER := append([]byte(nil), encoded...)
		oidDER[0] = byte(cryptobyte_asn1.OBJECT_IDENTIFIER)
		var objectID stdasn1.ObjectIdentifier
		rest, err := stdasn1.Unmarshal(oidDER, &objectID)
		if err != nil || len(rest) != 0 || len(objectID) == 0 {
			return fmt.Errorf("invalid registeredID")
		}
	}

	return nil
}
