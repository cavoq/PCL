package crl

import (
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
)

func TestEntryIndexResolvesIndirectIssuerInheritance(t *testing.T) {
	firstTime := time.Unix(1_700_000_001, 0).UTC()
	secondTime := time.Unix(1_700_000_002, 0).UTC()
	record := entryIndexRecord("list issuer", true, false, []x509ext.EntryFacts{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: firstTime,
		},
		{
			SerialNumber:   big.NewInt(2),
			RevocationTime: secondTime,
			ReasonCode: &x509ext.ReasonCodeExtensionFacts{
				Value: x509ext.CRLReasonKeyCompromise,
			},
			CertificateIssuer: entryIndexCertificateIssuer(
				x509ext.GeneralName{Tag: 6, RawValue: []byte("https://issuer.test")},
				entryIndexDirectoryName("first issuer"),
				entryIndexDirectoryName("first issuer"),
				entryIndexDirectoryName("alternate issuer"),
			),
		},
		{SerialNumber: big.NewInt(3)},
		{
			SerialNumber: big.NewInt(4),
			CertificateIssuer: entryIndexCertificateIssuer(
				entryIndexDirectoryName("second issuer"),
			),
		},
	})

	index := prepareEntryIndex(record)
	if index.invalidFor(false) || index.invalidFor(true) {
		t.Fatal("valid indirect issuer inheritance was marked invalid")
	}

	tests := []struct {
		name       string
		issuer     string
		serial     int64
		wantIndex  int
		wantReason int
		wantTime   time.Time
	}{
		{name: "list issuer before first transition", issuer: "list issuer", serial: 1, wantIndex: 0, wantTime: firstTime},
		{name: "transition applies to its entry", issuer: "first issuer", serial: 2, wantIndex: 1, wantReason: 1, wantTime: secondTime},
		{name: "alternate directory name", issuer: "alternate issuer", serial: 2, wantIndex: 1, wantReason: 1, wantTime: secondTime},
		{name: "transition is inherited", issuer: "first issuer", serial: 3, wantIndex: 2},
		{name: "alternate name is inherited", issuer: "alternate issuer", serial: 3, wantIndex: 2},
		{name: "later transition replaces issuer set", issuer: "second issuer", serial: 4, wantIndex: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := index.find(entryIndexTarget(test.issuer, big.NewInt(test.serial)))
			if !match.found || match.invalid || match.index != test.wantIndex ||
				match.reasonCode != test.wantReason || !match.revocationTime.Equal(test.wantTime) {
				t.Fatalf("match = %+v, want index %d, reason %d, time %v", match, test.wantIndex, test.wantReason, test.wantTime)
			}
		})
	}

	if match := index.find(entryIndexTarget("first issuer", big.NewInt(4))); match.found || match.invalid {
		t.Fatalf("replaced issuer unexpectedly matched: %+v", match)
	}
}

func TestEntryIndexRejectsInvalidIssuerTransitions(t *testing.T) {
	tests := []struct {
		name     string
		indirect bool
		issuer   *x509ext.CertificateIssuerExtensionFacts
	}{
		{
			name:   "certificateIssuer on direct CRL",
			issuer: entryIndexCertificateIssuer(entryIndexDirectoryName("entry issuer")),
		},
		{
			name:     "indirect issuer without directoryName",
			indirect: true,
			issuer: entryIndexCertificateIssuer(
				x509ext.GeneralName{Tag: 6, RawValue: []byte("https://issuer.test")},
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := entryIndexRecord("list issuer", test.indirect, false, []x509ext.EntryFacts{{
				SerialNumber:      big.NewInt(1),
				CertificateIssuer: test.issuer,
			}})
			index := prepareEntryIndex(record)
			if !index.invalidFor(false) || !index.invalidFor(true) {
				t.Fatal("invalid certificateIssuer transition was accepted")
			}
			if match := index.find(entryIndexTarget("entry issuer", big.NewInt(1))); !match.invalid {
				t.Fatalf("lookup through invalid issuer chain = %+v", match)
			}
		})
	}
}

func TestEntryIndexDuplicatesAreTargetSpecific(t *testing.T) {
	record := entryIndexRecord("list issuer", false, false, []x509ext.EntryFacts{
		{SerialNumber: big.NewInt(7)},
		{SerialNumber: big.NewInt(7)},
		{SerialNumber: big.NewInt(8)},
	})
	index := prepareEntryIndex(record)
	if index.invalidFor(false) || index.invalidFor(true) {
		t.Fatal("duplicate entry key incorrectly became a list-wide semantic failure")
	}
	if match := index.find(entryIndexTarget("list issuer", big.NewInt(7))); !match.invalid || match.found {
		t.Fatalf("duplicate target match = %+v, want invalid", match)
	}
	if match := index.find(entryIndexTarget("list issuer", big.NewInt(8))); !match.found || match.invalid || match.index != 2 {
		t.Fatalf("unrelated unique target match = %+v", match)
	}

	separateIssuers := entryIndexRecord("list issuer", true, false, []x509ext.EntryFacts{
		{
			SerialNumber: big.NewInt(9),
			CertificateIssuer: entryIndexCertificateIssuer(
				entryIndexDirectoryName("first issuer"),
				entryIndexDirectoryName("first issuer"),
			),
		},
		{
			SerialNumber: big.NewInt(9),
			CertificateIssuer: entryIndexCertificateIssuer(
				entryIndexDirectoryName("second issuer"),
			),
		},
	})
	separateIndex := prepareEntryIndex(separateIssuers)
	for _, test := range []struct {
		issuer    string
		wantIndex int
	}{
		{issuer: "first issuer", wantIndex: 0},
		{issuer: "second issuer", wantIndex: 1},
	} {
		match := separateIndex.find(entryIndexTarget(test.issuer, big.NewInt(9)))
		if !match.found || match.invalid || match.index != test.wantIndex {
			t.Fatalf("issuer %q match = %+v, want index %d", test.issuer, match, test.wantIndex)
		}
	}
}

func TestEntryIndexRoleSpecificSemantics(t *testing.T) {
	unspecified := &x509ext.ReasonCodeExtensionFacts{
		Value: x509ext.CRLReasonUnspecified,
	}
	remove := &x509ext.ReasonCodeExtensionFacts{
		Value: x509ext.CRLReasonRemoveFromCRL,
	}
	tests := []struct {
		name                string
		partitioned         bool
		entry               x509ext.EntryFacts
		wantCompleteInvalid bool
		wantDeltaInvalid    bool
	}{
		{
			name: "unsupported critical extension on unrelated entry",
			entry: x509ext.EntryFacts{
				SerialNumber:                     big.NewInt(99),
				UnsupportedCriticalExtensionOIDs: []string{"1.2.3.4"},
			},
			wantCompleteInvalid: true,
			wantDeltaInvalid:    true,
		},
		{
			name: "explicit unspecified in reason partition",
			entry: x509ext.EntryFacts{
				SerialNumber: big.NewInt(99), ReasonCode: unspecified,
			},
			partitioned:         true,
			wantCompleteInvalid: true,
			wantDeltaInvalid:    true,
		},
		{
			name: "absent reason in reason partition",
			entry: x509ext.EntryFacts{
				SerialNumber: big.NewInt(99),
			},
			partitioned: true,
		},
		{
			name: "unspecified outside reason partition",
			entry: x509ext.EntryFacts{
				SerialNumber: big.NewInt(99), ReasonCode: unspecified,
			},
		},
		{
			name: "removeFromCRL",
			entry: x509ext.EntryFacts{
				SerialNumber: big.NewInt(99), ReasonCode: remove,
			},
			wantCompleteInvalid: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			index := prepareEntryIndex(entryIndexRecord(
				"list issuer", false, test.partitioned, []x509ext.EntryFacts{test.entry},
			))
			if got := index.invalidFor(false); got != test.wantCompleteInvalid {
				t.Fatalf("complete invalid = %v, want %v", got, test.wantCompleteInvalid)
			}
			if got := index.invalidFor(true); got != test.wantDeltaInvalid {
				t.Fatalf("delta invalid = %v, want %v", got, test.wantDeltaInvalid)
			}
		})
	}
}

func TestEntryIndexPreservesSignedAndOptionalSerials(t *testing.T) {
	record := entryIndexRecord("list issuer", false, false, []x509ext.EntryFacts{
		{SerialNumber: nil},
		{SerialNumber: big.NewInt(0)},
		{SerialNumber: big.NewInt(7)},
		{SerialNumber: big.NewInt(-7)},
	})
	index := prepareEntryIndex(record)
	if len(index.byCertificate) != 3 {
		t.Fatalf("indexed key count = %d, want 3", len(index.byCertificate))
	}
	tests := []struct {
		name      string
		serial    *big.Int
		wantFound bool
		wantIndex int
	}{
		{name: "nil", serial: nil},
		{name: "zero", serial: big.NewInt(0), wantFound: true, wantIndex: 1},
		{name: "positive", serial: big.NewInt(7), wantFound: true, wantIndex: 2},
		{name: "negative", serial: big.NewInt(-7), wantFound: true, wantIndex: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := index.find(entryIndexTarget("list issuer", test.serial))
			if match.invalid || match.found != test.wantFound ||
				(test.wantFound && match.index != test.wantIndex) {
				t.Fatalf("match = %+v, want found %v at %d", match, test.wantFound, test.wantIndex)
			}
		})
	}
	if match := index.find(nil); match.found || match.invalid {
		t.Fatalf("nil certificate match = %+v", match)
	}
}

func entryIndexRecord(
	listIssuer string,
	indirect, partitioned bool,
	entries []x509ext.EntryFacts,
) decodedList {
	var issuingDistributionPoint *x509ext.IssuingDistributionPointFacts
	if indirect || partitioned {
		issuingDistributionPoint = &x509ext.IssuingDistributionPointFacts{
			IndirectCRL: indirect,
		}
		if partitioned {
			issuingDistributionPoint.OnlySomeReasons = &x509ext.ReasonFlags{}
		}
	}
	return decodedList{
		list: &x509.RevocationList{RawIssuer: []byte(listIssuer)},
		facts: x509ext.RevocationListFacts{
			IssuingDistributionPoint: issuingDistributionPoint,
			Entries:                  entries,
		},
	}
}

func entryIndexCertificateIssuer(
	names ...x509ext.GeneralName,
) *x509ext.CertificateIssuerExtensionFacts {
	return &x509ext.CertificateIssuerExtensionFacts{Names: names}
}

func entryIndexDirectoryName(raw string) x509ext.GeneralName {
	return x509ext.GeneralName{Tag: 4, RawValue: []byte(raw)}
}

func entryIndexTarget(issuer string, serial *big.Int) *x509.Certificate {
	return &x509.Certificate{RawIssuer: []byte(issuer), SerialNumber: serial}
}
