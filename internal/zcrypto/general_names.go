package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

type directoryString struct {
	Tag      int
	RawDER   []byte
	RawValue []byte
	Value    string
}

type ediPartyName struct {
	NameAssigner *directoryString
	PartyName    directoryString
}

// BuildGeneralName projects one decoded GeneralName. Certificate and CRL
// trees share this projection so the same name has the same node shape in
// every input.
func BuildGeneralName(name string, value x509ext.GeneralName) *node.Node {
	var (
		scalar        any = append([]byte(nil), value.RawValue...)
		typeID        string
		directoryName *node.Node
		edi           *ediPartyName
	)
	switch value.Tag {
	case 0:
		decodedTypeID, otherValue, err := decodeOtherName(value.RawValue)
		if err == nil {
			typeID = decodedTypeID
			scalar = otherValue
		}
	case 1, 2, 6:
		scalar = string(value.RawValue)
	case 4:
		directoryName = BuildRawName("directoryName", value.RawValue)
		scalar = directoryName.Value
	case 5:
		if decoded, err := decodeEDIPartyName(value.RawValue); err == nil {
			edi = &decoded
		}
	case 7:
		scalar = net.IP(value.RawValue).String()
	case 8:
		identifier, err := x509ext.DecodeRegisteredID(value.RawDER)
		if err == nil {
			scalar = identifier
		}
	}

	n := node.New(name, CloneScalar(scalar))
	n.Children["value"] = node.New("value", CloneScalar(scalar))
	n.Children["type"] = node.New("type", x509ext.GeneralNameType(value.Tag))
	n.Children["tag"] = node.New("tag", value.Tag)
	n.Children["raw"] = node.New("raw", append([]byte(nil), value.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), value.RawValue...))

	switch value.Tag {
	case 0:
		if typeID != "" {
			n.Children["typeID"] = node.New("typeID", typeID)
		}
	case 4:
		n.Children["directoryName"] = directoryName
	case 5:
		if edi != nil {
			if edi.NameAssigner != nil {
				n.Children["nameAssigner"] = buildDirectoryStringNode("nameAssigner", *edi.NameAssigner)
			}
			n.Children["partyName"] = buildDirectoryStringNode("partyName", edi.PartyName)
		}
	case 6:
		if uri, ok := scalar.(string); ok {
			if separator := strings.IndexByte(uri, ':'); separator >= 0 {
				n.Children["scheme"] = node.New("scheme", uri[:separator])
			}
		}
	}

	return n
}

// AddGeneralNames adds names to parent under their zero-based indexes.
func AddGeneralNames(parent *node.Node, names []x509ext.GeneralName) {
	for index, name := range names {
		key := strconv.Itoa(index)
		parent.Children[key] = BuildGeneralName(key, name)
	}
}

// CloneScalar copies byte-slice node values so projected nodes never alias
// decoder buffers. Other values are returned unchanged.
func CloneScalar(value any) any {
	if bytes, ok := value.([]byte); ok {
		return append([]byte(nil), bytes...)
	}
	return value
}

func decodeOtherName(content []byte) (string, []byte, error) {
	value := cryptobyte.String(content)
	var typeID stdasn1.ObjectIdentifier
	var otherValue cryptobyte.String
	if !value.ReadASN1ObjectIdentifier(&typeID) ||
		!value.ReadASN1(&otherValue, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!value.Empty() || otherValue.Empty() {
		return "", nil, fmt.Errorf("invalid otherName")
	}
	inner := otherValue
	var innerDER cryptobyte.String
	var innerTag cryptobyte_asn1.Tag
	if !inner.ReadAnyASN1Element(&innerDER, &innerTag) || !inner.Empty() {
		return "", nil, fmt.Errorf("otherName value must contain exactly one DER element")
	}
	return typeID.String(), append([]byte(nil), otherValue...), nil
}

func decodeEDIPartyName(content []byte) (ediPartyName, error) {
	value := cryptobyte.String(content)
	nameAssigner, present, err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(),
		"nameAssigner",
		false,
	)
	if err != nil {
		return ediPartyName{}, err
	}
	partyName, _, err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(1).Constructed().ContextSpecific(),
		"partyName",
		true,
	)
	if err != nil {
		return ediPartyName{}, err
	}
	if !value.Empty() {
		return ediPartyName{}, fmt.Errorf("unexpected ediPartyName data")
	}

	decoded := ediPartyName{PartyName: partyName}
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
) (directoryString, bool, error) {
	if !input.PeekASN1Tag(tag) {
		if required {
			return directoryString{}, false, fmt.Errorf("missing %s", field)
		}
		return directoryString{}, false, nil
	}

	var explicit cryptobyte.String
	if !input.ReadASN1(&explicit, tag) {
		return directoryString{}, false, fmt.Errorf("invalid %s", field)
	}

	var rawDER cryptobyte.String
	var stringTag cryptobyte_asn1.Tag
	if !explicit.ReadAnyASN1Element(&rawDER, &stringTag) || !explicit.Empty() {
		return directoryString{}, false, fmt.Errorf("invalid %s DirectoryString", field)
	}
	element := rawDER
	var rawValue cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&rawValue, &parsedTag) || !element.Empty() || parsedTag != stringTag {
		return directoryString{}, false, fmt.Errorf("invalid %s DirectoryString", field)
	}
	decoded, err := internalasn1.DecodeDirectoryString(int(stringTag), rawValue)
	if err != nil {
		return directoryString{}, false, fmt.Errorf("invalid %s: %w", field, err)
	}
	return directoryString{
		Tag:      int(stringTag),
		RawDER:   append([]byte(nil), rawDER...),
		RawValue: append([]byte(nil), rawValue...),
		Value:    decoded,
	}, true, nil
}

func buildDirectoryStringNode(name string, value directoryString) *node.Node {
	n := node.New(name, value.Value)
	n.Children["tag"] = node.New("tag", value.Tag)
	n.Children["encoding"] = node.New("encoding", internalasn1.StringTypeName(value.Tag))
	n.Children["raw"] = node.New("raw", append([]byte(nil), value.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), value.RawValue...))
	return n
}
