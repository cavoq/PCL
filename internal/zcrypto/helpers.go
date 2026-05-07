// Package zcrypto provides zcrypto conversion helpers.
package zcrypto

import (
	stdx509 "crypto/x509"

	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
)

// Extension OID to friendly name mapping
var extensionNames = map[string]string{
	"2.5.29.14":          "subjectKeyIdentifier",
	"2.5.29.15":          "keyUsage",
	"2.5.29.17":          "subjectAltName",
	"2.5.29.18":          "issuerAltName",
	"2.5.29.19":          "basicConstraints",
	"2.5.29.30":          "nameConstraints",
	"2.5.29.31":          "cRLDistributionPoints",
	"2.5.29.32":          "certificatePolicies",
	"2.5.29.35":          "authorityKeyIdentifier",
	"2.5.29.37":          "extKeyUsage",
	"1.3.6.1.5.5.7.1.1":  "authorityInfoAccess",
	"1.3.6.1.5.5.7.1.11": "subjectInfoAccess",
	"2.5.29.21":          "cRLReason",
	"2.5.29.29":          "cRLNumber",
	"2.5.29.20":          "cRLDistributionPoints", // Note: this is actually issuingDistributionPoint
	"1.3.6.1.5.5.7.48.1": "id-ad-ocsp",
	"1.3.6.1.5.5.7.48.2": "id-ad-caIssuers",
}

func ToStdCert(cert *zx509.Certificate) (*stdx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return stdx509.ParseCertificate(cert.Raw)
}

func FromStdCert(cert *stdx509.Certificate) (*zx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return zx509.ParseCertificate(cert.Raw)
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
	if len(pkixName.OrganizationIDs) > 0 {
		n.Children["organizationIdentifier"] = node.New("organizationIdentifier", pkixName.OrganizationIDs[0])
	}

	// EV-specific fields
	if len(pkixName.JurisdictionCountry) > 0 {
		n.Children["jurisdictionCountryName"] = node.New("jurisdictionCountryName", pkixName.JurisdictionCountry[0])
	}
	if len(pkixName.JurisdictionProvince) > 0 {
		n.Children["jurisdictionStateOrProvinceName"] = node.New("jurisdictionStateOrProvinceName", pkixName.JurisdictionProvince[0])
	}
	if len(pkixName.JurisdictionLocality) > 0 {
		n.Children["jurisdictionLocalityName"] = node.New("jurisdictionLocalityName", pkixName.JurisdictionLocality[0])
	}

	// Parse additional attributes from Names (e.g., businessCategory)
	// OID 2.5.4.15 = businessCategory
	for _, atv := range pkixName.Names {
		if len(atv.Type) == 4 && atv.Type[0] == 2 && atv.Type[1] == 5 && atv.Type[2] == 4 {
			switch atv.Type[3] {
			case 15: // businessCategory (2.5.4.15)
				if val, ok := atv.Value.(string); ok {
					n.Children["businessCategory"] = node.New("businessCategory", val)
				}
			}
		}
	}

	return n
}

func BuildExtensions(extensions []pkix.Extension) *node.Node {
	n := node.New("extensions", nil)

	for _, ext := range extensions {
		oidStr := ext.Id.String()
		extNode := node.New(oidStr, nil)
		extNode.Children["oid"] = node.New("oid", oidStr)
		extNode.Children["critical"] = node.New("critical", ext.Critical)
		extNode.Children["value"] = node.New("value", ext.Value)

		// Add friendly name if available
		if name, ok := extensionNames[oidStr]; ok {
			extNode.Children["name"] = node.New("name", name)
			// Also add the extension under its friendly name for easier access
			n.Children[name] = extNode
		}

		// Always add under OID
		n.Children[oidStr] = extNode
	}

	return n
}
