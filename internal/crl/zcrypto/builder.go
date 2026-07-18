// Package zcrypto provides zcrypto-based CRL parsing.
package zcrypto

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
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

func buildCRL(crl *x509.RevocationList) *node.Node {
	root := node.New("crl", nil)

	root.Children["issuer"] = zcrypto.BuildPkixName("issuer", crl.Issuer)
	root.Children["thisUpdate"] = node.New("thisUpdate", crl.ThisUpdate)
	if !crl.NextUpdate.IsZero() {
		root.Children["nextUpdate"] = node.New("nextUpdate", crl.NextUpdate)
	}
	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(crl)
	root.Children["tbsSignatureAlgorithm"] = buildTBSSignatureAlgorithm(crl)

	if crl.Number != nil {
		root.Children["crlNumber"] = node.New("crlNumber", crl.Number.String())
	}

	if keyIdentifier := AuthorityKeyIdentifier(crl); len(keyIdentifier) > 0 {
		root.Children["authorityKeyIdentifier"] = node.New("authorityKeyIdentifier", keyIdentifier)
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
	params := internalasn1.ParseSignedObjectAlgorithmParams(crl.Raw)
	return zcrypto.BuildAlgorithmIdentifier("signatureAlgorithm", crl.SignatureAlgorithm.String(), params)
}

func buildTBSSignatureAlgorithm(crl *x509.RevocationList) *node.Node {
	params := parseTBSCRLSignatureParams(crl.RawTBSRevocationList)
	return zcrypto.BuildAlgorithmIdentifier("tbsSignatureAlgorithm", crl.SignatureAlgorithm.String(), params)
}

func buildRevokedCertificates(revoked []x509.RevokedCertificate) *node.Node {
	n := node.New("revokedCertificates", len(revoked))

	for i, rc := range revoked {
		rcNode := node.New(fmt.Sprintf("%d", i), nil)
		if rc.SerialNumber != nil {
			rcNode.Children["serialNumber"] = node.New("serialNumber", rc.SerialNumber.String())
		}
		rcNode.Children["revocationDate"] = node.New("revocationDate", rc.RevocationTime)

		if len(rc.Extensions) > 0 {
			extsNode := zcrypto.BuildExtensions(rc.Extensions)
			if rc.ReasonCode != nil {
				if reasonNode, ok := extsNode.Children[oid.CRLReason]; ok {
					reasonNode.Children["rawValue"] = node.New("rawValue", reasonNode.Children["value"].Value)
					reasonNode.Children["value"] = node.New("value", *rc.ReasonCode)
				}
			}
			rcNode.Children["extensions"] = extsNode
		}

		n.Children[fmt.Sprintf("%d", i)] = rcNode
	}

	return n
}
