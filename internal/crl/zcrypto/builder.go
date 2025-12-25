package zcrypto

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"

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

func buildCRL(crl *x509.RevocationList) *node.Node {
	root := node.New("crl", nil)

	root.Children["issuer"] = zcrypto.BuildPkixName("issuer", crl.Issuer)
	root.Children["thisUpdate"] = node.New("thisUpdate", crl.ThisUpdate)
	root.Children["nextUpdate"] = node.New("nextUpdate", crl.NextUpdate)
	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(crl)

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
	n := node.New("signatureAlgorithm", nil)
	n.Children["algorithm"] = node.New("algorithm", crl.SignatureAlgorithm.String())
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

		if len(rc.Extensions) > 0 {
			rcNode.Children["extensions"] = zcrypto.BuildExtensions(rc.Extensions)
		}

		n.Children[fmt.Sprintf("%d", i)] = rcNode
	}

	return n
}
