package oid

import "testing"

func TestCRLExtensionOIDs(t *testing.T) {
	tests := map[string]string{
		"crl number":                 CRLNumber,
		"delta CRL indicator":        DeltaCRLIndicator,
		"issuing distribution point": IssuingDistributionPoint,
		"certificate issuer":         CertificateIssuer,
		"authority key identifier":   AuthorityKeyIdentifier,
	}
	want := map[string]string{
		"crl number":                 "2.5.29.20",
		"delta CRL indicator":        "2.5.29.27",
		"issuing distribution point": "2.5.29.28",
		"certificate issuer":         "2.5.29.29",
		"authority key identifier":   "2.5.29.35",
	}
	for name, got := range tests {
		if got != want[name] {
			t.Errorf("%s OID = %s, want %s", name, got, want[name])
		}
	}
	if got := NormalizeOID("issuingDistributionPoint"); got != IssuingDistributionPoint {
		t.Errorf("NormalizeOID = %s, want %s", got, IssuingDistributionPoint)
	}
}

func TestValidDotted(t *testing.T) {
	tests := map[string]bool{
		"1.2.840.113549.1.1.1": true,
		"2.999.3":              true,
		"0.39":                 true,
		"":                     false,
		"1":                    false,
		"3.1":                  false,
		"1.40":                 false,
		"1.02.3":               false,
		"1..3":                 false,
	}
	for value, want := range tests {
		if got := ValidDotted(value); got != want {
			t.Errorf("ValidDotted(%q) = %v, want %v", value, got, want)
		}
	}
}
