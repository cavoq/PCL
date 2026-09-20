package x509ext

import (
	"testing"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestExtensionIndexReportsPresenceAndUniqueness(t *testing.T) {
	const (
		firstOID  = "2.5.29.15"
		secondOID = "2.5.29.31"
	)
	index := NewExtensionIndex([]pkix.Extension{
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{1}},
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 31}, Critical: true, Value: []byte{2}},
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{3}},
	})

	tests := []struct {
		name       string
		identifier string
		present    bool
		unique     bool
		count      int
	}{
		{name: "absent", identifier: "2.5.29.46"},
		{name: "single", identifier: secondOID, present: true, unique: true, count: 1},
		{name: "duplicate", identifier: firstOID, present: true, count: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := index.Lookup(test.identifier)
			if match.Present() != test.present || match.Unique() != test.unique ||
				match.Count() != test.count {
				t.Fatalf(
					"Lookup(%q) = present:%t unique:%t count:%d",
					test.identifier,
					match.Present(),
					match.Unique(),
					match.Count(),
				)
			}
			_, ok := match.Extension()
			if ok != test.unique {
				t.Fatalf("Extension() ok = %t, want %t", ok, test.unique)
			}
		})
	}
}

func TestExtensionIndexPreservesOrderAndOwnsData(t *testing.T) {
	input := []pkix.Extension{
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 31}, Value: []byte{1}},
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 46}, Value: []byte{2}},
	}
	index := NewExtensionIndex(input)
	input[0].Id[3] = 99
	input[0].Value[0] = 99

	ordered := index.Extensions()
	if got := ordered[0].Id.String(); got != "2.5.29.31" {
		t.Fatalf("first extension OID = %q, want 2.5.29.31", got)
	}
	if ordered[0].Value[0] != 1 || ordered[1].Id.String() != "2.5.29.46" {
		t.Fatalf("ordered extensions changed: %#v", ordered)
	}

	ordered[0].Value[0] = 88
	match := index.Lookup("2.5.29.31")
	extension, ok := match.Extension()
	if !ok || extension.Value[0] != 1 {
		t.Fatalf("lookup after returned-value mutation = %#v, %t", extension, ok)
	}
	extension.Value[0] = 77
	again, _ := index.Lookup("2.5.29.31").Extension()
	if again.Value[0] != 1 {
		t.Fatalf("lookup exposed indexed data: %#v", again)
	}
}
