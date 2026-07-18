package zcrypto

import (
	"github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
)

// BuildAlgorithmIdentifier converts parsed AlgorithmIdentifier facts into the
// common node-tree representation used by certificates, CRLs, and OCSP.
func BuildAlgorithmIdentifier(name, displayName string, params asn1.ParamsState) *node.Node {
	n := node.New(name, nil)
	if params.Malformed {
		n.Children["malformed"] = node.New("malformed", true)
	}
	if displayName != "" {
		n.Children["algorithm"] = node.New("algorithm", displayName)
	}
	if params.OID != "" {
		n.Children["oid"] = node.New("oid", params.OID)
	}
	if len(params.RawDER) > 0 {
		n.Children["rawDER"] = node.New("rawDER", params.RawDER)
	}
	if paramsNode := buildAlgorithmIdentifierParams(params); paramsNode != nil {
		n.Children["parameters"] = paramsNode
	}
	return n
}

func buildAlgorithmIdentifierParams(params asn1.ParamsState) *node.Node {
	if params.IsAbsent || params.Malformed {
		return nil
	}

	n := node.New("parameters", nil)
	n.Children["null"] = node.New("null", params.IsNull)

	if params.NamedCurve != "" {
		n.Children["namedCurve"] = node.New("namedCurve", params.NamedCurve)
	}
	if params.PSS != nil {
		n.Children["pss"] = buildPSSParams(params.PSS)
	}
	if params.OAEP != nil {
		n.Children["oaep"] = buildOAEPParams(params.OAEP)
	}

	return n
}

func buildPSSParams(pss *asn1.PSSParams) *node.Node {
	n := node.New("pss", nil)
	n.Children["hashAlgorithm"] = buildNestedAlgorithmIdentifier(pss.HashAlgorithm)
	n.Children["hashAlgorithmSet"] = node.New("hashAlgorithmSet", pss.HashAlgorithmSet)
	n.Children["maskGenAlgorithm"] = buildNestedAlgorithmIdentifier(pss.MaskGenAlgorithm)
	n.Children["maskGenAlgorithmSet"] = node.New("maskGenAlgorithmSet", pss.MaskGenAlgorithmSet)
	n.Children["saltLength"] = node.New("saltLength", pss.SaltLength)
	n.Children["saltLengthSet"] = node.New("saltLengthSet", pss.SaltLengthSet)
	n.Children["trailerField"] = node.New("trailerField", pss.TrailerField)
	n.Children["trailerFieldSet"] = node.New("trailerFieldSet", pss.TrailerFieldSet)
	return n
}

func buildOAEPParams(oaep *asn1.OAEPParams) *node.Node {
	n := node.New("oaep", nil)
	n.Children["hashAlgorithm"] = buildNestedAlgorithmIdentifier(oaep.HashAlgorithm)
	n.Children["hashAlgorithmSet"] = node.New("hashAlgorithmSet", oaep.HashAlgorithmSet)
	n.Children["maskGenAlgorithm"] = buildNestedAlgorithmIdentifier(oaep.MaskGenAlgorithm)
	n.Children["maskGenAlgorithmSet"] = node.New("maskGenAlgorithmSet", oaep.MaskGenAlgorithmSet)
	n.Children["pSourceAlgorithm"] = buildNestedAlgorithmIdentifier(oaep.PSourceAlgorithm)
	n.Children["pSourceAlgorithmSet"] = node.New("pSourceAlgorithmSet", oaep.PSourceAlgorithmSet)
	return n
}

func buildNestedAlgorithmIdentifier(algorithm asn1.AlgorithmIdentifier) *node.Node {
	n := node.New("algorithm", nil)
	if algorithm.OID != "" {
		n.Children["oid"] = node.New("oid", algorithm.OID)
	}

	params := algorithm.Params
	if params.IsAbsent {
		return n
	}
	paramsNode := buildAlgorithmIdentifierParams(params)
	if paramsNode == nil {
		return n
	}
	// For algorithms such as MGF1, parameters is itself an
	// AlgorithmIdentifier. ParamsState.OID and RawDER describe that nested
	// identifier, not the enclosing MGF1 identifier.
	if params.OID != "" {
		paramsNode.Children["oid"] = node.New("oid", params.OID)
	}
	if len(params.RawDER) > 0 {
		paramsNode.Children["rawDER"] = node.New("rawDER", params.RawDER)
	}
	n.Children["parameters"] = paramsNode
	return n
}
