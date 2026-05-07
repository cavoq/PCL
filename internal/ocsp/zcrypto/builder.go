// Package zcrypto provides zcrypto-based OCSP response parsing.
package zcrypto

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
)

type OCSPBuilder struct{}

func NewOCSPBuilder() *OCSPBuilder {
	return &OCSPBuilder{}
}

func (b *OCSPBuilder) Build(resp *ocsp.Response) *node.Node {
	return buildOCSP(resp)
}

func BuildTree(resp *ocsp.Response) *node.Node {
	return NewOCSPBuilder().Build(resp)
}

func buildOCSP(resp *ocsp.Response) *node.Node {
	root := node.New("ocsp", nil)

	// Status
	root.Children["status"] = node.New("status", statusString(resp.Status))

	// SerialNumber
	if resp.SerialNumber != nil {
		root.Children["serialNumber"] = node.New("serialNumber", resp.SerialNumber.String())
	}

	// Times
	root.Children["producedAt"] = node.New("producedAt", resp.ProducedAt)
	root.Children["thisUpdate"] = node.New("thisUpdate", resp.ThisUpdate)
	if !resp.NextUpdate.IsZero() {
		root.Children["nextUpdate"] = node.New("nextUpdate", resp.NextUpdate)
	}

	// Revocation info (if revoked)
	if resp.Status == ocsp.Revoked {
		root.Children["revokedAt"] = node.New("revokedAt", resp.RevokedAt)
		root.Children["revocationReason"] = node.New("revocationReason", resp.RevocationReason)
	}

	// Signature algorithm (from BasicOCSPResponse)
	// OCSP has only one signatureAlgorithm field, not separate TBS and outer like certificates/CRLs
	params := ParseOCSPSignatureAlgorithmParams(resp.Raw)
	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(resp.SignatureAlgorithm, params)
	// For consistency with cert/CRL tree structure, we also create tbsSignatureAlgorithm
	// pointing to the same signature algorithm
	root.Children["tbsSignatureAlgorithm"] = buildSignatureAlgorithm(resp.SignatureAlgorithm, params)

	// Responder ID
	root.Children["responderID"] = buildResponderID(resp)

	// Issuer hash
	root.Children["issuerHash"] = node.New("issuerHash", hashString(resp.IssuerHash))

	// Extensions
	if len(resp.Extensions) > 0 {
		root.Children["extensions"] = buildExtensions(resp.Extensions)
	}

	// Nonce extension (RFC 9654)
	// Parse nonce from responseExtensions (inside TBSResponseData), NOT from singleExtensions.
	// The nonce is in responseExtensions, which are NOT exposed by golang.org/x/crypto/ocsp.
	// We parse it directly from the raw OCSP response.
	nonce := ParseNonceFromRaw(resp.Raw)
	nonceNode := node.New("nonce", nil)
	nonceNode.Children["present"] = node.New("present", nonce.Present)
	if nonce.Present {
		nonceNode.Children["value"] = node.New("value", nonce.Value)
		nonceNode.Children["length"] = node.New("length", nonce.Length)
		nonceNode.Children["hexValue"] = node.New("hexValue", nonce.HexValue)
	}
	root.Children["nonce"] = nonceNode

	return root
}

func buildExtensions(extensions []pkix.Extension) *node.Node {
	n := node.New("extensions", nil)

	for _, ext := range extensions {
		extNode := node.New(ext.Id.String(), nil)
		extNode.Children["oid"] = node.New("oid", ext.Id.String())
		extNode.Children["critical"] = node.New("critical", ext.Critical)
		extNode.Children["value"] = node.New("value", ext.Value)
		n.Children[ext.Id.String()] = extNode
	}

	return n
}

func buildSignatureAlgorithm(algo x509.SignatureAlgorithm, params asn1.ParamsState) *node.Node {
	n := node.New("signatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", algo.String())
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

func buildNestedAlgorithmID(algo asn1.AlgorithmIdentifier) *node.Node {
	n := node.New("algorithm", nil)
	n.Children["oid"] = node.New("oid", algo.OID)
	paramNode := buildAlgorithmIDParams(algo.Params)
	if paramNode != nil {
		n.Children["parameters"] = paramNode
	}
	return n
}

func buildResponderID(resp *ocsp.Response) *node.Node {
	n := node.New("responderID", nil)

	if len(resp.RawResponderName) > 0 {
		n.Children["byName"] = node.New("byName", true)
		n.Children["rawName"] = node.New("rawName", resp.RawResponderName)
	}

	if len(resp.ResponderKeyHash) > 0 {
		n.Children["byKey"] = node.New("byKey", true)
		n.Children["keyHash"] = node.New("keyHash", fmt.Sprintf("%x", resp.ResponderKeyHash))
	}

	return n
}

func statusString(status int) string {
	switch status {
	case ocsp.Good:
		return "Good"
	case ocsp.Revoked:
		return "Revoked"
	case ocsp.Unknown:
		return "Unknown"
	default:
		return fmt.Sprintf("Unknown(%d)", status)
	}
}

func hashString(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("Unknown(%d)", h)
	}
}
