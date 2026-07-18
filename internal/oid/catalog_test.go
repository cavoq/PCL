package oid

import (
	"reflect"
	"testing"

	"github.com/zmap/zcrypto/x509"
)

func TestParse(t *testing.T) {
	got, err := Parse(OCSPNonce)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	if !reflect.DeepEqual([]int(got), want) {
		t.Fatalf("Parse() = %v, want %v", got, want)
	}

	if _, err := Parse("1.03.6"); err == nil {
		t.Fatal("Parse() accepted a non-canonical identifier")
	}
}

func TestExtensionName(t *testing.T) {
	tests := map[string]string{
		KeyUsage:            "keyUsage",
		NameConstraints:     "nameConstraints",
		CertificatePolicies: "certificatePolicies",
		AuthorityInfoAccess: "authorityInfoAccess",
		DeltaCRLIndicator:   "deltaCRLIndicator",
		CertificateIssuer:   "certificateIssuer",
	}
	for identifier, want := range tests {
		got, ok := ExtensionName(identifier)
		if !ok || got != want {
			t.Errorf("ExtensionName(%q) = %q, %v; want %q, true", identifier, got, ok, want)
		}
	}

	if _, ok := ExtensionName(AccessMethodOCSP); ok {
		t.Fatal("access method was classified as an extension")
	}
}

func TestAttributeOID(t *testing.T) {
	tests := map[string]string{
		"commonName":                      AttributeCommonName,
		"businessCategory":                AttributeBusinessCategory,
		"domainComponent":                 AttributeDomainComponent,
		"jurisdictionStateOrProvince":     AttributeJurisdictionStateOrProvince,
		"jurisdictionStateOrProvinceName": AttributeJurisdictionStateOrProvince,
	}
	for name, want := range tests {
		got, ok := AttributeOID(name)
		if !ok || got != want {
			t.Errorf("AttributeOID(%q) = %q, %v; want %q, true", name, got, ok, want)
		}
	}
}

func TestExtendedKeyUsageCatalog(t *testing.T) {
	tests := map[string]struct {
		usage x509.ExtKeyUsage
		oid   string
	}{
		"serverAuth":      {usage: x509.ExtKeyUsageServerAuth, oid: ServerAuth},
		"clientAuth":      {usage: x509.ExtKeyUsageClientAuth, oid: ClientAuth},
		"codeSigning":     {usage: x509.ExtKeyUsageCodeSigning, oid: CodeSigning},
		"emailProtection": {usage: x509.ExtKeyUsageEmailProtection, oid: EmailProtection},
		"timeStamping":    {usage: x509.ExtKeyUsageTimeStamping, oid: TimeStamping},
		"ocspSigning":     {usage: x509.ExtKeyUsageOcspSigning, oid: OCSPSigning},
	}
	for name, want := range tests {
		usage, ok := ExtKeyUsage(name)
		if !ok || usage != want.usage {
			t.Errorf("ExtKeyUsage(%q) = %v, %v; want %v, true", name, usage, ok, want.usage)
		}
		identifier, ok := ExtKeyUsageOID(name)
		if !ok || identifier != want.oid {
			t.Errorf("ExtKeyUsageOID(%q) = %q, %v; want %q, true", name, identifier, ok, want.oid)
		}
		if got := ExtKeyUsageToOID(want.usage); got != want.oid {
			t.Errorf("ExtKeyUsageToOID(%v) = %q, want %q", want.usage, got, want.oid)
		}
		if got := NormalizeOID(name); got != want.oid {
			t.Errorf("NormalizeOID(%q) = %q, want %q", name, got, want.oid)
		}
	}

	usage, ok := ExtKeyUsage("any")
	if !ok || usage != x509.ExtKeyUsageAny {
		t.Fatalf("ExtKeyUsage(any) = %v, %v", usage, ok)
	}
	if _, ok := ExtKeyUsageOID("any"); ok {
		t.Fatal("ExtKeyUsageOID(any) unexpectedly returned an identifier")
	}
	if got := NormalizeOID("any"); got != "any" {
		t.Fatalf("NormalizeOID(any) = %q, want unchanged", got)
	}
}
