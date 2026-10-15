package certnode

import (
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

func ParsePolicyMappingsStrict(extValue []byte) (*node.Node, error) {
	mappings, err := x509ext.DecodePolicyMappingsStrict(extValue)
	if err != nil {
		return nil, err
	}
	return projectPolicyMappings(extValue, mappings), nil
}

func projectPolicyMappings(raw []byte, mappings []x509ext.PolicyMapping) *node.Node {
	n := node.New("policyMappings", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), raw...))
	n.Children["count"] = node.New("count", len(mappings))
	mappingsNode := node.New("mappings", nil)
	n.Children["mappings"] = mappingsNode
	for index, mapping := range mappings {
		key := strconv.Itoa(index)
		mappingNode := node.New(key, nil)
		mappingNode.Children["issuerDomainPolicy"] = node.New(
			"issuerDomainPolicy",
			mapping.IssuerDomainPolicy,
		)
		mappingNode.Children["subjectDomainPolicy"] = node.New(
			"subjectDomainPolicy",
			mapping.SubjectDomainPolicy,
		)
		mappingNode.Children["raw"] = node.New("raw", append([]byte(nil), mapping.RawDER...))
		mappingsNode.Children[key] = mappingNode
	}
	return n
}

func ParsePolicyConstraintsStrict(extValue []byte) (*node.Node, error) {
	decoded, err := x509ext.DecodePolicyConstraintsStrict(extValue)
	if err != nil {
		return nil, err
	}
	return projectPolicyConstraints(decoded), nil
}

func projectPolicyConstraints(decoded x509ext.PolicyConstraints) *node.Node {
	n := node.New("policyConstraints", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["requireExplicitPolicyPresent"] = node.New(
		"requireExplicitPolicyPresent",
		decoded.RequireExplicitPolicyPresent,
	)
	n.Children["inhibitPolicyMappingPresent"] = node.New(
		"inhibitPolicyMappingPresent",
		decoded.InhibitPolicyMappingPresent,
	)
	if decoded.RequireExplicitPolicyPresent {
		integer := x509ext.NonNegativeInteger{
			Int:     decoded.RequireExplicitPolicy,
			Decimal: decoded.RequireExplicitPolicyDecimal,
			FitsInt: decoded.RequireExplicitPolicyFitsInt,
		}
		value := node.New("requireExplicitPolicy", integer.Scalar())
		value.Children["raw"] = node.New(
			"raw",
			append([]byte(nil), decoded.RequireExplicitPolicyRaw...),
		)
		value.Children["decimal"] = node.New("decimal", integer.Decimal)
		value.Children["fitsInt"] = node.New("fitsInt", integer.FitsInt)
		n.Children["requireExplicitPolicy"] = value
	}
	if decoded.InhibitPolicyMappingPresent {
		integer := x509ext.NonNegativeInteger{
			Int:     decoded.InhibitPolicyMapping,
			Decimal: decoded.InhibitPolicyMappingDecimal,
			FitsInt: decoded.InhibitPolicyMappingFitsInt,
		}
		value := node.New("inhibitPolicyMapping", integer.Scalar())
		value.Children["raw"] = node.New(
			"raw",
			append([]byte(nil), decoded.InhibitPolicyMappingRaw...),
		)
		value.Children["decimal"] = node.New("decimal", integer.Decimal)
		value.Children["fitsInt"] = node.New("fitsInt", integer.FitsInt)
		n.Children["inhibitPolicyMapping"] = value
	}
	return n
}

func ParseInhibitAnyPolicyStrict(extValue []byte) (*node.Node, error) {
	skipCerts, err := x509ext.DecodeInhibitAnyPolicyStrict(extValue)
	if err != nil {
		return nil, err
	}
	n := node.New("inhibitAnyPolicy", skipCerts.Scalar())
	skipCertsNode := node.New("skipCerts", skipCerts.Scalar())
	skipCertsNode.Children["decimal"] = node.New("decimal", skipCerts.Decimal)
	skipCertsNode.Children["fitsInt"] = node.New("fitsInt", skipCerts.FitsInt)
	n.Children["skipCerts"] = skipCertsNode
	n.Children["raw"] = node.New("raw", append([]byte(nil), extValue...))
	return n, nil
}
