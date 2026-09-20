package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	nameprojector "github.com/cavoq/PCL/internal/zcrypto"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type parsedGeneralName = x509ext.GeneralName

type parsedDirectoryString struct {
	Tag      int
	RawDER   []byte
	RawValue []byte
	Value    string
}

type parsedEDIPartyName struct {
	NameAssigner *parsedDirectoryString
	PartyName    parsedDirectoryString
}

func generalNameType(tag int) string {
	return x509ext.GeneralNameType(tag)
}

func readGeneralName(input *cryptobyte.String) (parsedGeneralName, error) {
	return x509ext.ReadGeneralName(input)
}

func buildParsedGeneralName(name string, value parsedGeneralName) *node.Node {
	var (
		scalar        any = append([]byte(nil), value.RawValue...)
		typeID        string
		directoryName *node.Node
		ediPartyName  *parsedEDIPartyName
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
		directoryName = nameprojector.BuildRawName("directoryName", value.RawValue)
		scalar = directoryName.Value
	case 5:
		if decoded, err := decodeEDIPartyName(value.RawValue); err == nil {
			ediPartyName = &decoded
		}
	case 7:
		scalar = net.IP(value.RawValue).String()
	case 8:
		identifier, err := decodeRegisteredID(value.RawDER)
		if err == nil {
			scalar = identifier
		}
	}

	n := node.New(name, cloneGeneralNameScalar(scalar))
	n.Children["value"] = node.New("value", cloneGeneralNameScalar(scalar))
	n.Children["type"] = node.New("type", generalNameType(value.Tag))
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
		if ediPartyName != nil {
			if ediPartyName.NameAssigner != nil {
				n.Children["nameAssigner"] = buildDirectoryStringNode(
					"nameAssigner",
					*ediPartyName.NameAssigner,
				)
			}
			n.Children["partyName"] = buildDirectoryStringNode("partyName", ediPartyName.PartyName)
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

func cloneGeneralNameScalar(value any) any {
	if bytes, ok := value.([]byte); ok {
		return append([]byte(nil), bytes...)
	}
	return value
}

func addParsedGeneralNames(target *node.Node, names []parsedGeneralName) {
	for index, name := range names {
		key := fmt.Sprintf("%d", index)
		target.Children[key] = buildParsedGeneralName(key, name)
	}
}

func parseGeneralNames(value []byte) ([]parsedGeneralName, error) {
	return x509ext.DecodeGeneralNames(value)
}

func buildSubjectAltName(cert *x509.Certificate) *node.Node {
	return buildCertificateGeneralNames("subjectAltName", cert.Extensions, oid.SubjectAlternativeName)
}

func buildIssuerAltName(cert *x509.Certificate) *node.Node {
	return buildCertificateGeneralNames("issuerAltName", cert.Extensions, oid.IssuerAlternativeName)
}

func buildCertificateGeneralNames(
	name string,
	extensions []pkix.Extension,
	targetOID string,
) *node.Node {
	n := node.New(name, nil)
	extension, ok := findExtension(extensions, targetOID)
	if !ok {
		return n
	}

	names, err := parseGeneralNames(extension.Value)
	if err != nil {
		n.Children["raw"] = node.New("raw", append([]byte(nil), extension.Value...))
		n.Children["malformed"] = node.New("malformed", true)
		return n
	}

	n.Value = len(names)
	entries := node.New("entries", nil)
	n.Children["entries"] = entries
	typeCounts := make(map[int]int)
	for index, parsed := range names {
		key := strconv.Itoa(index)
		entry := buildParsedGeneralName(key, parsed)
		entries.Children[key] = entry

		// Preserve the established direct directoryName paths while the shared
		// GeneralName projection also retains its nested directoryName object.
		if directoryName := entry.Children["directoryName"]; directoryName != nil {
			for childName, child := range directoryName.Children {
				if childName != "raw" {
					entry.Children[childName] = child
				}
			}
		}

		collectionName := generalNameType(parsed.Tag)
		collection := n.Children[collectionName]
		if collection == nil {
			collection = node.New(collectionName, nil)
			n.Children[collectionName] = collection
		}

		typeIndex := strconv.Itoa(typeCounts[parsed.Tag])
		collection.Children[typeIndex] = aliasGeneralNameNode(typeIndex, entry)
		typeCounts[parsed.Tag]++
	}

	return n
}

// aliasGeneralNameNode gives the per-type collection its compact numeric name
// while sharing the canonical entry's immutable value metadata and decoded
// children. This avoids parsing and copying every GeneralName twice.
func aliasGeneralNameNode(name string, canonical *node.Node) *node.Node {
	return &node.Node{
		Name:     name,
		Value:    canonical.Value,
		Children: canonical.Children,
	}
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

func decodeEDIPartyName(content []byte) (parsedEDIPartyName, error) {
	value := cryptobyte.String(content)
	nameAssigner, present, err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(),
		"nameAssigner",
		false,
	)
	if err != nil {
		return parsedEDIPartyName{}, err
	}
	partyName, _, err := readExplicitDirectoryString(
		&value,
		cryptobyte_asn1.Tag(1).Constructed().ContextSpecific(),
		"partyName",
		true,
	)
	if err != nil {
		return parsedEDIPartyName{}, err
	}
	if !value.Empty() {
		return parsedEDIPartyName{}, fmt.Errorf("unexpected ediPartyName data")
	}

	decoded := parsedEDIPartyName{PartyName: partyName}
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
) (parsedDirectoryString, bool, error) {
	if !input.PeekASN1Tag(tag) {
		if required {
			return parsedDirectoryString{}, false, fmt.Errorf("missing %s", field)
		}
		return parsedDirectoryString{}, false, nil
	}

	var explicit cryptobyte.String
	if !input.ReadASN1(&explicit, tag) {
		return parsedDirectoryString{}, false, fmt.Errorf("invalid %s", field)
	}

	var rawDER cryptobyte.String
	var stringTag cryptobyte_asn1.Tag
	if !explicit.ReadAnyASN1Element(&rawDER, &stringTag) || !explicit.Empty() {
		return parsedDirectoryString{}, false, fmt.Errorf("invalid %s DirectoryString", field)
	}
	element := rawDER
	var rawValue cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&rawValue, &parsedTag) || !element.Empty() || parsedTag != stringTag {
		return parsedDirectoryString{}, false, fmt.Errorf("invalid %s DirectoryString", field)
	}
	decoded, err := internalasn1.DecodeDirectoryString(int(stringTag), rawValue)
	if err != nil {
		return parsedDirectoryString{}, false, fmt.Errorf("invalid %s: %w", field, err)
	}
	return parsedDirectoryString{
		Tag:      int(stringTag),
		RawDER:   append([]byte(nil), rawDER...),
		RawValue: append([]byte(nil), rawValue...),
		Value:    decoded,
	}, true, nil
}

func buildDirectoryStringNode(name string, value parsedDirectoryString) *node.Node {
	n := node.New(name, value.Value)
	n.Children["tag"] = node.New("tag", value.Tag)
	n.Children["encoding"] = node.New("encoding", internalasn1.StringTypeName(value.Tag))
	n.Children["raw"] = node.New("raw", append([]byte(nil), value.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), value.RawValue...))
	return n
}

func decodeRegisteredID(encoded []byte) (string, error) {
	return x509ext.DecodeRegisteredID(encoded)
}
