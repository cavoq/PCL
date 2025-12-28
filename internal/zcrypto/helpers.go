package zcrypto

import (
	stdx509 "crypto/x509"

	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
)

func ToStdCert(cert *zx509.Certificate) (*stdx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return stdx509.ParseCertificate(cert.Raw)
}

func BuildPkixName(name string, pkixName pkix.Name) *node.Node {
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
	if len(pkixName.StreetAddress) > 0 {
		n.Children["streetAddress"] = node.New("streetAddress", pkixName.StreetAddress[0])
	}
	if len(pkixName.PostalCode) > 0 {
		n.Children["postalCode"] = node.New("postalCode", pkixName.PostalCode[0])
	}
	if pkixName.SerialNumber != "" {
		n.Children["serialNumber"] = node.New("serialNumber", pkixName.SerialNumber)
	}

	return n
}

func BuildExtensions(extensions []pkix.Extension) *node.Node {
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
