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

// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//
//	AccessDescription ::= SEQUENCE {
//	    accessMethod    OBJECT IDENTIFIER,
//	    accessLocation  GeneralName }
type decodedAccessDescription struct {
	Method   string
	Location parsedGeneralName
}

// ParseAIA parses the Authority Information Access extension. It is retained
// as a compatibility wrapper; new builder code should use ParseAIAStrict so a
// malformed extension cannot be mistaken for an empty or partial value.
func ParseAIA(extValue []byte) *node.Node {
	n, err := ParseAIAStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNode("authorityInfoAccess", isEmptySequence(extValue))
}

// ParseAIAStrict parses exactly one AuthorityInfoAccessSyntax value.
func ParseAIAStrict(extValue []byte) (*node.Node, error) {
	accessDescriptions, err := decodeAuthorityInformationAccess(extValue)
	if err != nil {
		return nil, err
	}
	return projectAuthorityInformationAccess(accessDescriptions), nil
}

func decodeAuthorityInformationAccess(extValue []byte) ([]decodedAccessDescription, error) {
	input := cryptobyte.String(extValue)
	var encodedDescriptions cryptobyte.String
	if !input.ReadASN1(&encodedDescriptions, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid AuthorityInfoAccessSyntax sequence")
	}
	if encodedDescriptions.Empty() {
		return nil, fmt.Errorf("AuthorityInfoAccessSyntax must not be empty")
	}

	var descriptions []decodedAccessDescription
	for index := 0; !encodedDescriptions.Empty(); index++ {
		description, err := decodeAccessDescription(&encodedDescriptions, index)
		if err != nil {
			return nil, err
		}
		descriptions = append(descriptions, description)
	}
	return descriptions, nil
}

func decodeAccessDescription(input *cryptobyte.String, index int) (decodedAccessDescription, error) {
	var encodedDescription cryptobyte.String
	if !input.ReadASN1(&encodedDescription, cryptobyte_asn1.SEQUENCE) {
		return decodedAccessDescription{}, fmt.Errorf("invalid AccessDescription %d", index)
	}

	var method stdasn1.ObjectIdentifier
	if !encodedDescription.ReadASN1ObjectIdentifier(&method) {
		return decodedAccessDescription{}, fmt.Errorf("invalid accessMethod in AccessDescription %d", index)
	}
	location, err := readGeneralName(&encodedDescription)
	if err != nil {
		return decodedAccessDescription{}, fmt.Errorf(
			"invalid accessLocation in AccessDescription %d: %w",
			index,
			err,
		)
	}
	if !encodedDescription.Empty() {
		return decodedAccessDescription{}, fmt.Errorf("unexpected data in AccessDescription %d", index)
	}

	return decodedAccessDescription{
		Method:   method.String(),
		Location: location,
	}, nil
}

func projectAuthorityInformationAccess(descriptions []decodedAccessDescription) *node.Node {
	n := node.New("authorityInfoAccess", nil)
	descriptionsNode := node.New("accessDescriptions", nil)
	n.Children["accessDescriptions"] = descriptionsNode
	n.Children["empty"] = node.New("empty", false)

	containsOCSP := false
	containsCAIssuers := false
	for index, description := range descriptions {
		key := strconv.Itoa(index)
		descriptionNode := node.New(key, nil)
		descriptionNode.Children["accessMethod"] = node.New("accessMethod", description.Method)
		descriptionNode.Children["accessLocation"] = buildParsedGeneralName("accessLocation", description.Location)
		descriptionsNode.Children[key] = descriptionNode

		containsOCSP = containsOCSP || description.Method == oid.AccessMethodOCSP
		containsCAIssuers = containsCAIssuers || description.Method == oid.AccessMethodCAIssuers
	}

	n.Children["count"] = node.New("count", len(descriptions))
	n.Children["containsOCSP"] = node.New("containsOCSP", containsOCSP)
	n.Children["containsCaIssuers"] = node.New("containsCaIssuers", containsCAIssuers)
	return n
}
