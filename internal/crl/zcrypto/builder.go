package zcrypto

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
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

	root.Children["issuer"] = buildPkixName("issuer", crl.Issuer)
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
		root.Children["extensions"] = buildExtensions(crl.Extensions)
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
			rcNode.Children["extensions"] = buildExtensions(rc.Extensions)
		}

		n.Children[fmt.Sprintf("%d", i)] = rcNode
	}

	return n
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

func buildPkixName(name string, pkixName pkix.Name) *node.Node {
	n := node.New(name, nil)

	if len(pkixName.Country) > 0 {
		n.Children["countryName"] = node.New("countryName", pkixName.Country[0])
	}
	if len(pkixName.Organization) > 0 {
		n.Children["organizationName"] = node.New("organizationName", pkixName.Organization[0])
	}
	if len(pkixName.OrganizationalUnit) > 0 {
		n.Children["organizationalUnitName"] = node.New("organizationalUnitName", pkixName.OrganizationalUnit[0])
	}
	if pkixName.CommonName != "" {
		n.Children["commonName"] = node.New("commonName", pkixName.CommonName)
	}
	if len(pkixName.Locality) > 0 {
		n.Children["localityName"] = node.New("localityName", pkixName.Locality[0])
	}
	if len(pkixName.Province) > 0 {
		n.Children["stateOrProvinceName"] = node.New("stateOrProvinceName", pkixName.Province[0])
	}

	return n
}
