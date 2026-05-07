// Package zcrypto provides zcrypto-based CRL parsing.
package zcrypto

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/zcrypto"
)

type CRLBuilder struct{}

func NewCRLBuilder() *CRLBuilder {
	return &CRLBuilder{}
}

func (b *CRLBuilder) Build(crl *x509.RevocationList) *node.Node {
	return buildCRL(crl)
}

func BuildTree(crl *x509.RevocationList) *node.Node {
	return NewCRLBuilder().Build(crl)
}

// BuildTreeWithChain builds CRL node tree with CA status determined from issuer chain.
// isCACRL is set to true if the CRL issuer is a CA certificate (Root or Intermediate).
func BuildTreeWithChain(crl *x509.RevocationList, issuerCerts []*x509.Certificate) *node.Node {
	n := buildCRL(crl)
	if n == nil {
		return nil
	}

	// Determine if CRL issuer is a CA
	isCACRL := false
	crlIssuer := crl.Issuer.String()

	for _, cert := range issuerCerts {
		if cert != nil && cert.Subject.String() == crlIssuer {
			isCACRL = cert.IsCA
			break
		}
	}

	n.Children["isCACRL"] = node.New("isCACRL", isCACRL)
	return n
}

func buildCRL(crl *x509.RevocationList) *node.Node {
	root := node.New("crl", nil)

	root.Children["issuer"] = zcrypto.BuildPkixName("issuer", crl.Issuer)
	root.Children["thisUpdate"] = node.New("thisUpdate", crl.ThisUpdate)
	root.Children["nextUpdate"] = node.New("nextUpdate", crl.NextUpdate)
	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(crl)
	root.Children["tbsSignatureAlgorithm"] = buildTBSSignatureAlgorithm(crl)

	if crl.Number != nil {
		root.Children["crlNumber"] = node.New("crlNumber", crl.Number.String())
	}

	if len(crl.AuthorityKeyId) > 0 {
		root.Children["authorityKeyIdentifier"] = node.New("authorityKeyIdentifier", crl.AuthorityKeyId)
	}

	if len(crl.RevokedCertificates) > 0 {
		root.Children["revokedCertificates"] = buildRevokedCertificates(crl.RevokedCertificates)
	}

	if len(crl.Extensions) > 0 {
		root.Children["extensions"] = zcrypto.BuildExtensions(crl.Extensions)
	}

	if len(crl.Signature) > 0 {
		root.Children["signatureValue"] = node.New("signatureValue", crl.Signature)
	}

	return root
}

func buildSignatureAlgorithm(crl *x509.RevocationList) *node.Node {
	params := ParseCRLSignatureAlgorithmParams(crl.Raw)
	n := node.New("signatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", crl.SignatureAlgorithm.String())
	n.Children["oid"] = node.New("oid", params.OID)
	paramNode := buildAlgorithmIDParams(params)
	if paramNode != nil {
		n.Children["parameters"] = paramNode
	}
	return n
}

func buildTBSSignatureAlgorithm(crl *x509.RevocationList) *node.Node {
	params := ParseTBSCRLSignatureParams(crl.RawTBSRevocationList)
	n := node.New("tbsSignatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", crl.SignatureAlgorithm.String())
	n.Children["oid"] = node.New("oid", params.OID)
	paramNode := buildAlgorithmIDParams(params)
	if paramNode != nil {
		n.Children["parameters"] = paramNode
	}
	return n
}

func buildAlgorithmIDParams(params asn1.ParamsState) *node.Node {
	// If parameters are absent, do NOT create a node.
	// This allows the `absent` operator to work correctly.
	if params.IsAbsent {
		return nil
	}

	// If parameters are NULL, create node with null=true.
	// This allows the `isNull` operator to work correctly.
	n := node.New("parameters", nil)
	n.Children["null"] = node.New("null", params.IsNull)

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

	n.Children["hashAlgorithm"] = buildNestedAlgorithmID(pss.HashAlgorithm)
	n.Children["hashAlgorithmSet"] = node.New("hashAlgorithmSet", pss.HashAlgorithmSet)
	n.Children["maskGenAlgorithm"] = buildNestedAlgorithmID(pss.MaskGenAlgorithm)
	n.Children["maskGenAlgorithmSet"] = node.New("maskGenAlgorithmSet", pss.MaskGenAlgorithmSet)
	n.Children["saltLength"] = node.New("saltLength", pss.SaltLength)
	n.Children["saltLengthSet"] = node.New("saltLengthSet", pss.SaltLengthSet)
	n.Children["trailerField"] = node.New("trailerField", pss.TrailerField)
	n.Children["trailerFieldSet"] = node.New("trailerFieldSet", pss.TrailerFieldSet)

	return n
}

func buildOAEPParams(oaep *asn1.OAEPParams) *node.Node {
	n := node.New("oaep", nil)

	n.Children["hashAlgorithm"] = buildNestedAlgorithmID(oaep.HashAlgorithm)
	n.Children["hashAlgorithmSet"] = node.New("hashAlgorithmSet", oaep.HashAlgorithmSet)
	n.Children["maskGenAlgorithm"] = buildNestedAlgorithmID(oaep.MaskGenAlgorithm)
	n.Children["maskGenAlgorithmSet"] = node.New("maskGenAlgorithmSet", oaep.MaskGenAlgorithmSet)
	n.Children["pSourceAlgorithm"] = buildNestedAlgorithmID(oaep.PSourceAlgorithm)
	n.Children["pSourceAlgorithmSet"] = node.New("pSourceAlgorithmSet", oaep.PSourceAlgorithmSet)

	return n
}

func buildNestedAlgorithmID(algo asn1.AlgorithmIdentifier) *node.Node {
	n := node.New("algorithm", nil)
	n.Children["oid"] = node.New("oid", algo.OID)
	paramNode := buildAlgorithmIDParams(algo.Params)
	if paramNode != nil {
		n.Children["parameters"] = paramNode
	}
	return n
}

func buildRevokedCertificates(revoked []x509.RevokedCertificate) *node.Node {
	n := node.New("revokedCertificates", len(revoked))

	for i, rc := range revoked {
		rcNode := node.New(fmt.Sprintf("%d", i), nil)
		if rc.SerialNumber != nil {
			rcNode.Children["serialNumber"] = node.New("serialNumber", rc.SerialNumber.String())
		}
		rcNode.Children["revocationDate"] = node.New("revocationDate", rc.RevocationTime)

		// Add parsed reason code if present
		if rc.ReasonCode != nil {
			extNode := node.New("2.5.29.21", nil)
			extNode.Children["oid"] = node.New("oid", "2.5.29.21")
			extNode.Children["critical"] = node.New("critical", false)
			extNode.Children["value"] = node.New("value", *rc.ReasonCode)
			extsNode := node.New("extensions", nil)
			extsNode.Children["2.5.29.21"] = extNode
			rcNode.Children["extensions"] = extsNode
		}

		// Also keep raw extensions for other extension types
		if len(rc.Extensions) > 0 {
			// Merge with existing extensions node or create new one
			extsNode := rcNode.Children["extensions"]
			if extsNode == nil {
				extsNode = node.New("extensions", nil)
				rcNode.Children["extensions"] = extsNode
			}
			for _, ext := range rc.Extensions {
				// Skip reason code - already handled above
				if ext.Id.String() == "2.5.29.21" {
					continue
				}
				extNode := node.New(ext.Id.String(), nil)
				extNode.Children["oid"] = node.New("oid", ext.Id.String())
				extNode.Children["critical"] = node.New("critical", ext.Critical)
				extNode.Children["value"] = node.New("value", ext.Value)
				extsNode.Children[ext.Id.String()] = extNode
			}
		}

		n.Children[fmt.Sprintf("%d", i)] = rcNode
	}

	return n
}
