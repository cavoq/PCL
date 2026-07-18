// Package zcrypto provides zcrypto-based OCSP response parsing.
package zcrypto

import (
	"crypto"
	"fmt"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/node"
	sharedzcrypto "github.com/cavoq/PCL/internal/zcrypto"
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
	root.Children["signatureAlgorithm"] = sharedzcrypto.BuildAlgorithmIdentifier("signatureAlgorithm", resp.SignatureAlgorithm.String(), params)
	// For consistency with cert/CRL tree structure, we also create tbsSignatureAlgorithm
	// pointing to the same signature algorithm
	root.Children["tbsSignatureAlgorithm"] = sharedzcrypto.BuildAlgorithmIdentifier("tbsSignatureAlgorithm", resp.SignatureAlgorithm.String(), params)

	// Responder ID
	root.Children["responderID"] = buildResponderID(resp)

	// Issuer hash
	root.Children["issuerHash"] = node.New("issuerHash", hashString(resp.IssuerHash))

	// Extensions
	if len(resp.Extensions) > 0 {
		root.Children["extensions"] = sharedzcrypto.BuildStandardExtensions(resp.Extensions)
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
