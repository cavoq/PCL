package zcrypto

import (
	"strconv"
	"strings"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

func buildCertificatePoliciesNode(decoded decodedCertificatePolicies) *node.Node {
	root := node.New("certificatePolicies", nil)
	policyInformations := node.New("policyInformations", nil)
	root.Children["policyInformations"] = policyInformations

	for policyIndex, policy := range decoded.Policies {
		index := strconv.Itoa(policyIndex)
		policyName, _ := oid.CertificatePolicyName(policy.OID)
		policyNode := buildPolicyInformationNode(index, policy, policyName)
		policyInformations.Children[index] = policyNode
		root.Children[policy.OID] = policyNode
		if policyName != "" {
			root.Children[policyName] = policyNode
		}
	}
	return root
}

func buildPolicyInformationNode(
	name string,
	decoded decodedPolicyInformation,
	policyName string,
) *node.Node {
	policyNode := node.New(name, nil)
	policyNode.Children["policyIdentifier"] = node.New("policyIdentifier", decoded.OID)
	if policyName != "" {
		policyNode.Children["name"] = node.New("name", policyName)
	}
	if len(decoded.Qualifiers) > 0 {
		policyNode.Children["policyQualifiers"] = buildPolicyQualifiersNode(decoded.Qualifiers)
	}
	return policyNode
}

func buildPolicyQualifiersNode(decoded []decodedPolicyQualifier) *node.Node {
	qualifiersNode := node.New("policyQualifiers", nil)
	for qualifierIndex, qualifier := range decoded {
		index := strconv.Itoa(qualifierIndex)
		qualifierNode := buildPolicyQualifierNode(index, qualifier)
		qualifiersNode.Children[index] = qualifierNode
		qualifiersNode.Children[qualifier.OID] = qualifierNode
	}
	qualifiersNode.Children["count"] = node.New("count", len(decoded))
	return qualifiersNode
}

func buildPolicyQualifierNode(name string, decoded decodedPolicyQualifier) *node.Node {
	qualifierNode := node.New(name, nil)
	qualifierNode.Children["policyQualifierId"] = node.New("policyQualifierId", decoded.OID)

	switch decoded.Kind {
	case cpsPolicyQualifier:
		qualifierNode.Children["cpsURI"] = node.New("cpsURI", decoded.CPSURI)
		qualifierNode.Children["type"] = node.New("type", "cps")
		qualifierNode.Children["encoding"] = node.New("encoding", "ia5String")
		if separator := strings.IndexByte(decoded.CPSURI, ':'); separator >= 0 {
			qualifierNode.Children["scheme"] = node.New("scheme", decoded.CPSURI[:separator])
		}
	case userNoticePolicyQualifier:
		qualifierNode.Children["type"] = node.New("type", "userNotice")
		qualifierNode.Children["userNotice"] = buildUserNoticeNode(*decoded.UserNotice)
	default:
		qualifierNode.Children["type"] = node.New("type", "unknown")
		qualifierNode.Children["raw"] = node.New("raw", decoded.Raw)
	}
	return qualifierNode
}

func buildUserNoticeNode(decoded decodedUserNotice) *node.Node {
	noticeNode := node.New("userNotice", nil)
	if decoded.Reference != nil {
		noticeNode.Children["noticeReference"] = buildNoticeReferenceNode(*decoded.Reference)
	}
	if decoded.ExplicitText != nil {
		explicitTextNode := buildDisplayTextNode("explicitText", *decoded.ExplicitText)
		explicitTextNode.Children["tag"] = node.New("tag", int(decoded.ExplicitText.Tag))
		noticeNode.Children["explicitText"] = explicitTextNode
	}
	return noticeNode
}

func buildNoticeReferenceNode(decoded decodedNoticeReference) *node.Node {
	referenceNode := node.New("noticeReference", nil)
	referenceNode.Children["organization"] = buildDisplayTextNode("organization", decoded.Organization)

	numbersNode := node.New("noticeNumbers", nil)
	for numberIndex, number := range decoded.Numbers {
		index := strconv.Itoa(numberIndex)
		numbersNode.Children[index] = node.New(index, number)
	}
	numbersNode.Children["count"] = node.New("count", len(decoded.Numbers))
	referenceNode.Children["noticeNumbers"] = numbersNode
	return referenceNode
}

func buildDisplayTextNode(name string, decoded decodedDisplayText) *node.Node {
	displayTextNode := node.New(name, nil)
	displayTextNode.Children["value"] = node.New("value", decoded.Value)
	displayTextNode.Children["encoding"] = node.New(
		"encoding",
		internalasn1.StringTypeName(int(decoded.Tag)),
	)
	return displayTextNode
}
