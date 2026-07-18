package oid

import "testing"

func TestAttributeCatalogRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		oid  string
	}{
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
		{name: "jurisdictionLocalityName", oid: AttributeJurisdictionLocality},
		{name: "jurisdictionStateOrProvinceName", oid: AttributeJurisdictionStateOrProvince},
		{name: "jurisdictionCountryName", oid: AttributeJurisdictionCountry},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identifier, ok := AttributeOID(test.name)
			if !ok || identifier != test.oid {
				t.Fatalf("AttributeOID(%q) = %q, %v; want %q, true", test.name, identifier, ok, test.oid)
			}

			name, ok := AttributeName(test.oid)
			if !ok || name != test.name {
				t.Fatalf("AttributeName(%q) = %q, %v; want %q, true", test.oid, name, ok, test.name)
			}
		})
	}
}

func TestAttributeOIDAliases(t *testing.T) {
	tests := map[string]string{
		"jurisdictionLocality":        AttributeJurisdictionLocality,
		"jurisdictionStateOrProvince": AttributeJurisdictionStateOrProvince,
		"jurisdictionCountry":         AttributeJurisdictionCountry,
	}

	for alias, want := range tests {
		got, ok := AttributeOID(alias)
		if !ok || got != want {
			t.Errorf("AttributeOID(%q) = %q, %v; want %q, true", alias, got, ok, want)
		}
	}
}

func TestAttributeCatalogIsUnique(t *testing.T) {
	names := make(map[string]struct{}, len(attributeCatalog))
	identifiers := make(map[string]struct{}, len(attributeCatalog))

	for _, attribute := range attributeCatalog {
		if _, exists := names[attribute.name]; exists {
			t.Errorf("duplicate canonical attribute name %q", attribute.name)
		}
		names[attribute.name] = struct{}{}

		if _, exists := identifiers[attribute.oid]; exists {
			t.Errorf("attribute OID %q has more than one canonical name", attribute.oid)
		}
		identifiers[attribute.oid] = struct{}{}
	}
}

func TestUnknownAttributeLookup(t *testing.T) {
	if _, ok := AttributeOID("unknown"); ok {
		t.Fatal("AttributeOID accepted an unknown name")
	}
	if _, ok := AttributeName("1.2.3.4"); ok {
		t.Fatal("AttributeName accepted an unknown identifier")
	}
}
