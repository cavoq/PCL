package oid

import (
	"reflect"
	"sort"
	"testing"
)

func TestExtensionProcessableAtIsLocationSpecific(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		location   ExtensionLocation
		want       bool
	}{
		{name: "certificate key usage", identifier: KeyUsage, location: ExtensionInCertificate, want: true},
		{name: "certificate key usage at CRL", identifier: KeyUsage, location: ExtensionInCRL},
		{name: "CRL number deferred to P3", identifier: CRLNumber, location: ExtensionInCRL},
		{name: "CRL number at certificate", identifier: CRLNumber, location: ExtensionInCertificate},
		{name: "entry reason deferred to P3", identifier: CRLReason, location: ExtensionInCRLEntry},
		{name: "entry reason at CRL", identifier: CRLReason, location: ExtensionInCRL},
		{name: "newly processed certificate extension", identifier: PolicyMappings, location: ExtensionInCertificate, want: true},
		{name: "certificate AKI lacks strict malformed projection", identifier: AuthorityKeyIdentifier, location: ExtensionInCertificate},
		{name: "certificate SKI lacks strict malformed projection", identifier: SubjectKeyIdentifier, location: ExtensionInCertificate},
		{name: "known but unprocessed certificate extension", identifier: PrivateKeyUsagePeriod, location: ExtensionInCertificate},
		{name: "known but P3-only CRL extension", identifier: IssuingDistributionPoint, location: ExtensionInCRL},
		{name: "unknown extension", identifier: "1.2.3.4", location: ExtensionInCertificate},
		{
			name:       "combined locations do not broaden support",
			identifier: AuthorityKeyIdentifier,
			location:   ExtensionInCertificate | ExtensionInCRL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ExtensionProcessableAt(test.identifier, test.location); got != test.want {
				t.Fatalf("ExtensionProcessableAt(%q, %d) = %v, want %v", test.identifier, test.location, got, test.want)
			}
		})
	}
}

func TestProcessedExtensionRegistryIsAValidIdentitySubset(t *testing.T) {
	seen := make(map[ExtensionLocation]map[string]struct{})
	for _, definition := range processedExtensionRegistry {
		if definition.location != ExtensionInCertificate &&
			definition.location != ExtensionInCRL &&
			definition.location != ExtensionInCRLEntry {
			t.Errorf("processed extension %q has non-specific location %d", definition.identifier, definition.location)
		}
		if !ExtensionKnownAt(definition.identifier, definition.location) {
			t.Errorf("processed extension %q is not defined at location %d", definition.identifier, definition.location)
		}
		identifiers := seen[definition.location]
		if identifiers == nil {
			identifiers = make(map[string]struct{})
			seen[definition.location] = identifiers
		}
		if _, duplicate := identifiers[definition.identifier]; duplicate {
			t.Errorf("duplicate processed extension %q at location %d", definition.identifier, definition.location)
		}
		identifiers[definition.identifier] = struct{}{}
	}
}

func TestProcessedExtensionRegistryStableSets(t *testing.T) {
	want := map[ExtensionLocation][]string{
		ExtensionInCertificate: {
			AuthorityInfoAccess,
			BasicConstraints,
			CertificatePolicies,
			CRLDistributionPoints,
			ExtendedKeyUsage,
			InhibitAnyPolicy,
			IssuerAlternativeName,
			KeyUsage,
			NameConstraints,
			PolicyConstraints,
			PolicyMappings,
			SubjectAlternativeName,
		},
	}

	got := make(map[ExtensionLocation][]string)
	for _, definition := range processedExtensionRegistry {
		got[definition.location] = append(got[definition.location], definition.identifier)
	}
	for location := range got {
		sort.Strings(got[location])
	}
	for location := range want {
		sort.Strings(want[location])
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("processed extension sets = %#v, want %#v", got, want)
	}
}
