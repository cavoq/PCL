// Package zcrypto provides zcrypto conversion helpers.
package zcrypto

import (
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"

	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

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

func BuildPkixName(name string, pkixName zpkix.Name) *node.Node {
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

	// Parse additional attributes from Names (e.g., businessCategory).
	for _, atv := range pkixName.Names {
		if atv.Type.String() == oid.AttributeBusinessCategory {
			if val, ok := atv.Value.(string); ok {
				n.Children["businessCategory"] = node.New("businessCategory", val)
			}
		}
	}

	return n
}

type extensionFacts struct {
	oid      string
	critical bool
	value    []byte
}

func BuildExtensions(extensions []zpkix.Extension) *node.Node {
	facts := make([]extensionFacts, 0, len(extensions))
	for _, extension := range extensions {
		facts = append(facts, extensionFacts{
			oid:      extension.Id.String(),
			critical: extension.Critical,
			value:    extension.Value,
		})
	}
	return buildExtensions(facts)
}

// BuildStandardExtensions projects extensions from Go's standard x509 types
// into the same representation used for zcrypto certificate and CRL inputs.
func BuildStandardExtensions(extensions []stdpkix.Extension) *node.Node {
	facts := make([]extensionFacts, 0, len(extensions))
	for _, extension := range extensions {
		facts = append(facts, extensionFacts{
			oid:      extension.Id.String(),
			critical: extension.Critical,
			value:    extension.Value,
		})
	}
	return buildExtensions(facts)
}

func buildExtensions(extensions []extensionFacts) *node.Node {
	n := node.New("extensions", nil)

	for _, ext := range extensions {
		oidStr := ext.oid
		extNode := node.New(oidStr, nil)
		extNode.Children["oid"] = node.New("oid", oidStr)
		extNode.Children["critical"] = node.New("critical", ext.critical)
		extNode.Children["value"] = node.New("value", ext.value)

		// Add friendly name if available
		if name, ok := oid.ExtensionName(oidStr); ok {
			extNode.Children["name"] = node.New("name", name)
			// Also add the extension under its friendly name for easier access
			n.Children[name] = extNode
		}

		// Always add under OID
		n.Children[oidStr] = extNode
	}

	return n
}
