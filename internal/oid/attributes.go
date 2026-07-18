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
	AttributeBusinessCategory            = "2.5.4.15"
	AttributeGivenName                   = "2.5.4.42"
	AttributeOrganizationIdentifier      = "2.5.4.97"
	AttributeDomainComponent             = "0.9.2342.19200300.100.1.25"
	AttributeJurisdictionLocality        = "1.3.6.1.4.1.311.60.2.1.1"
	AttributeJurisdictionStateOrProvince = "1.3.6.1.4.1.311.60.2.1.2"
	AttributeJurisdictionCountry         = "1.3.6.1.4.1.311.60.2.1.3"
)

var attributeOIDsByName = map[string]string{
	"commonName":                      AttributeCommonName,
	"surname":                         AttributeSurname,
	"serialNumber":                    AttributeSerialNumber,
	"countryName":                     AttributeCountryName,
	"localityName":                    AttributeLocalityName,
	"stateOrProvinceName":             AttributeStateOrProvinceName,
	"streetAddress":                   AttributeStreetAddress,
	"organizationName":                AttributeOrganizationName,
	"organizationalUnitName":          AttributeOrganizationalUnitName,
	"businessCategory":                AttributeBusinessCategory,
	"givenName":                       AttributeGivenName,
	"organizationIdentifier":          AttributeOrganizationIdentifier,
	"domainComponent":                 AttributeDomainComponent,
	"jurisdictionLocality":            AttributeJurisdictionLocality,
	"jurisdictionLocalityName":        AttributeJurisdictionLocality,
	"jurisdictionStateOrProvince":     AttributeJurisdictionStateOrProvince,
	"jurisdictionStateOrProvinceName": AttributeJurisdictionStateOrProvince,
	"jurisdictionCountry":             AttributeJurisdictionCountry,
	"jurisdictionCountryName":         AttributeJurisdictionCountry,
}

// AttributeOID returns the identifier for a projected distinguished-name
// attribute. Both standards names and the existing jurisdiction node aliases
// are accepted.
func AttributeOID(name string) (string, bool) {
	identifier, ok := attributeOIDsByName[name]
	return identifier, ok
}
