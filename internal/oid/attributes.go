package oid

const (
	AttributeCommonName                  = "2.5.4.3"
	AttributeSurname                     = "2.5.4.4"
	AttributeSerialNumber                = "2.5.4.5"
	AttributeCountryName                 = "2.5.4.6"
	AttributeLocalityName                = "2.5.4.7"
	AttributeStateOrProvinceName         = "2.5.4.8"
	AttributeStreetAddress               = "2.5.4.9"
	AttributeOrganizationName            = "2.5.4.10"
	AttributeOrganizationalUnitName      = "2.5.4.11"
	AttributeTitle                       = "2.5.4.12"
	AttributeBusinessCategory            = "2.5.4.15"
	AttributePostalCode                  = "2.5.4.17"
	AttributeNameOID                     = "2.5.4.41"
	AttributeGivenName                   = "2.5.4.42"
	AttributeInitials                    = "2.5.4.43"
	AttributeGenerationQualifier         = "2.5.4.44"
	AttributeDNQualifier                 = "2.5.4.46"
	AttributePseudonym                   = "2.5.4.65"
	AttributeOrganizationIdentifier      = "2.5.4.97"
	AttributeEmailAddress                = "1.2.840.113549.1.9.1"
	AttributeDomainComponent             = "0.9.2342.19200300.100.1.25"
	AttributeJurisdictionLocality        = "1.3.6.1.4.1.311.60.2.1.1"
	AttributeJurisdictionStateOrProvince = "1.3.6.1.4.1.311.60.2.1.2"
	AttributeJurisdictionCountry         = "1.3.6.1.4.1.311.60.2.1.3"
)

type attributeDefinition struct {
	name    string
	oid     string
	aliases []string
}

var attributeCatalog = []attributeDefinition{
	{name: "commonName", oid: AttributeCommonName},
	{name: "surname", oid: AttributeSurname},
	{name: "serialNumber", oid: AttributeSerialNumber},
	{name: "countryName", oid: AttributeCountryName},
	{name: "localityName", oid: AttributeLocalityName},
	{name: "stateOrProvinceName", oid: AttributeStateOrProvinceName},
	{name: "streetAddress", oid: AttributeStreetAddress},
	{name: "organizationName", oid: AttributeOrganizationName},
	{name: "organizationalUnitName", oid: AttributeOrganizationalUnitName},
	{name: "title", oid: AttributeTitle},
	{name: "businessCategory", oid: AttributeBusinessCategory},
	{name: "postalCode", oid: AttributePostalCode},
	{name: "name", oid: AttributeNameOID},
	{name: "givenName", oid: AttributeGivenName},
	{name: "initials", oid: AttributeInitials},
	{name: "generationQualifier", oid: AttributeGenerationQualifier},
	{name: "dnQualifier", oid: AttributeDNQualifier},
	{name: "pseudonym", oid: AttributePseudonym},
	{name: "organizationIdentifier", oid: AttributeOrganizationIdentifier},
	{name: "emailAddress", oid: AttributeEmailAddress},
	{name: "domainComponent", oid: AttributeDomainComponent},
	{
		name:    "jurisdictionLocalityName",
		oid:     AttributeJurisdictionLocality,
		aliases: []string{"jurisdictionLocality"},
	},
	{
		name:    "jurisdictionStateOrProvinceName",
		oid:     AttributeJurisdictionStateOrProvince,
		aliases: []string{"jurisdictionStateOrProvince"},
	},
	{
		name:    "jurisdictionCountryName",
		oid:     AttributeJurisdictionCountry,
		aliases: []string{"jurisdictionCountry"},
	},
}

var attributeOIDsByName, attributeNamesByOID = buildAttributeCatalog()

func buildAttributeCatalog() (map[string]string, map[string]string) {
	byName := make(map[string]string, len(attributeCatalog))
	byOID := make(map[string]string, len(attributeCatalog))

	for _, attribute := range attributeCatalog {
		if _, exists := byOID[attribute.oid]; exists {
			panic("duplicate distinguished-name attribute OID: " + attribute.oid)
		}
		byOID[attribute.oid] = attribute.name

		names := append([]string{attribute.name}, attribute.aliases...)
		for _, name := range names {
			if _, exists := byName[name]; exists {
				panic("duplicate distinguished-name attribute name: " + name)
			}
			byName[name] = attribute.oid
		}
	}

	return byName, byOID
}

// AttributeOID returns the identifier for a projected distinguished-name
// attribute. Both standard names and the existing jurisdiction node aliases
// are accepted.
func AttributeOID(name string) (string, bool) {
	identifier, ok := attributeOIDsByName[name]
	return identifier, ok
}

// AttributeName returns the canonical policy-facing name for a distinguished-
// name attribute identifier.
func AttributeName(identifier string) (string, bool) {
	name, ok := attributeNamesByOID[identifier]
	return name, ok
}
