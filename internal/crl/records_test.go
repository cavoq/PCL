package crl

import (
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestUniqueDecodedListsDistinguishesFallbackIssuersInEitherOrder(t *testing.T) {
	tests := []struct {
		name      string
		rawIssuer []byte
	}{
		{name: "raw issuer absent"},
		{name: "raw issuer present", rawIssuer: []byte("shared raw issuer")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := identityTestCRL("First CRL Issuer")
			first.RawIssuer = append([]byte(nil), test.rawIssuer...)
			second := identityTestCRL("Second CRL Issuer")
			second.RawIssuer = append([]byte(nil), test.rawIssuer...)

			assertDistinctListsHaveStableOrder(t, first, second)
		})
	}
}

func TestUniqueDecodedListsDistinguishesSignatureAlgorithms(t *testing.T) {
	first := identityTestCRL("CRL Issuer")
	secondValue := *first
	secondValue.SignatureAlgorithm = x509.SHA256WithRSA

	assertDistinctListsHaveStableOrder(t, first, &secondValue)
}

func TestUniqueDecodedListsCollapsesExactDuplicates(t *testing.T) {
	first := identityTestCRL("CRL Issuer")
	duplicateValue := *first
	duplicate := &duplicateValue

	records := uniqueDecodedLists([]*x509.RevocationList{first, duplicate, first})
	if len(records) != 1 {
		t.Fatalf("unique records = %d, want 1", len(records))
	}
	if records[0].list != first {
		t.Fatal("deduplication did not retain the first exact duplicate")
	}
	if records[0].fingerprint != revocationListFingerprint(duplicate) {
		t.Fatal("exact duplicates have different fingerprints")
	}
}

func TestRevocationListFingerprintIsPresenceAware(t *testing.T) {
	withoutNumber := identityTestCRL("CRL Issuer")
	withZeroNumberValue := *withoutNumber
	withZeroNumberValue.Number = new(big.Int)

	if revocationListFingerprint(withoutNumber) == revocationListFingerprint(&withZeroNumberValue) {
		t.Fatal("an absent CRL number and an explicitly present zero have the same fingerprint")
	}
}

func TestRevocationListFingerprintIncludesSerialNumberSign(t *testing.T) {
	positive := identityTestCRL("CRL Issuer")
	positive.RevokedCertificates = []x509.RevokedCertificate{{
		SerialNumber:   big.NewInt(7),
		RevocationTime: positive.ThisUpdate,
	}}
	negativeValue := *positive
	negativeValue.RevokedCertificates = append(
		[]x509.RevokedCertificate(nil),
		positive.RevokedCertificates...,
	)
	negativeValue.RevokedCertificates[0].SerialNumber = big.NewInt(-7)

	if revocationListFingerprint(positive) == revocationListFingerprint(&negativeValue) {
		t.Fatal("positive and negative entry serial numbers have the same fingerprint")
	}
}

func assertDistinctListsHaveStableOrder(
	t *testing.T,
	first, second *x509.RevocationList,
) {
	t.Helper()
	if revocationListFingerprint(first) == revocationListFingerprint(second) {
		t.Fatal("distinct CRLs have the same fingerprint")
	}

	forward := uniqueDecodedLists([]*x509.RevocationList{first, second})
	reverse := uniqueDecodedLists([]*x509.RevocationList{second, first})
	if len(forward) != 2 || len(reverse) != 2 {
		t.Fatalf("unique record counts = %d and %d, want 2", len(forward), len(reverse))
	}
	for index := range forward {
		if forward[index].list != reverse[index].list {
			t.Fatalf("record order depends on input order at index %d", index)
		}
	}
}

func identityTestCRL(issuer string) *x509.RevocationList {
	return &x509.RevocationList{
		Raw:                  []byte("raw CRL"),
		RawTBSRevocationList: []byte("raw TBS CRL"),
		Issuer:               pkix.Name{CommonName: issuer},
		Signature:            []byte("signature"),
		SignatureAlgorithm:   x509.UnknownSignatureAlgorithm,
		ThisUpdate:           time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC),
		NextUpdate:           time.Date(2026, time.August, 15, 10, 0, 0, 0, time.UTC),
	}
}
