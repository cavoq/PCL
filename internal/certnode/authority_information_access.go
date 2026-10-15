package certnode

import (
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
)

// ParseAIAStrict parses exactly one AuthorityInfoAccessSyntax value.
func ParseAIAStrict(extValue []byte) (*node.Node, error) {
	accessDescriptions, err := x509ext.DecodeAuthorityInformationAccess(extValue)
	if err != nil {
		return nil, err
	}
	return projectAuthorityInformationAccess(accessDescriptions), nil
}

func projectAuthorityInformationAccess(descriptions []x509ext.AccessDescription) *node.Node {
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
		descriptionNode.Children["accessLocation"] = x509node.BuildGeneralName("accessLocation", description.Location)
		descriptionsNode.Children[key] = descriptionNode

		containsOCSP = containsOCSP || description.Method == oid.AccessMethodOCSP
		containsCAIssuers = containsCAIssuers || description.Method == oid.AccessMethodCAIssuers
	}

	n.Children["count"] = node.New("count", len(descriptions))
	n.Children["containsOCSP"] = node.New("containsOCSP", containsOCSP)
	n.Children["containsCaIssuers"] = node.New("containsCaIssuers", containsCAIssuers)
	return n
}
