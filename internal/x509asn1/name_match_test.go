package x509asn1

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"sort"
	"testing"
)

type testAttribute struct {
	oid   stdasn1.ObjectIdentifier
	tag   int
	value string
}

var (
	oidCountry    = stdasn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrg        = stdasn1.ObjectIdentifier{2, 5, 4, 10}
	oidCommonName = stdasn1.ObjectIdentifier{2, 5, 4, 3}
)

// testName encodes a Name with one RDN per element of rdns.
func testName(t *testing.T, rdns ...[]testAttribute) []byte {
	t.Helper()
	var content []byte
	for _, rdn := range rdns {
		var elements [][]byte
		for _, attribute := range rdn {
			value, err := stdasn1.Marshal(stdasn1.RawValue{Tag: attribute.tag, Bytes: []byte(attribute.value)})
			if err != nil {
				t.Fatal(err)
			}
			oidDER, err := stdasn1.Marshal(attribute.oid)
			if err != nil {
				t.Fatal(err)
			}
			elements = append(elements, EncodeSequence(append(oidDER, value...)))
		}
		// DER orders the attributes of a SET OF by their encodings.
		sort.Slice(elements, func(i, j int) bool { return bytes.Compare(elements[i], elements[j]) < 0 })
		set := bytes.Join(elements, nil)
		content = append(content, append([]byte{0x31, byte(len(set))}, set...)...)
	}
	return EncodeSequence(content)
}

func TestNamesMatchRFC5280Section71(t *testing.T) {
	base := testName(t,
		[]testAttribute{{oidCountry, 19, "US"}},
		[]testAttribute{{oidOrg, 19, "Test Certificates 2011"}},
		[]testAttribute{{oidCommonName, 19, "Good CA"}},
	)
	tests := []struct {
		name  string
		other []byte
		want  bool
	}{
		{"identical", base, true},
		{"case insensitive", testName(t,
			[]testAttribute{{oidCountry, 19, "us"}},
			[]testAttribute{{oidOrg, 19, "TEST CERTIFICATES 2011"}},
			[]testAttribute{{oidCommonName, 19, "good ca"}}), true},
		{"insignificant whitespace", testName(t,
			[]testAttribute{{oidCountry, 19, " US"}},
			[]testAttribute{{oidOrg, 19, "Test  Certificates   2011 "}},
			[]testAttribute{{oidCommonName, 19, "Good CA"}}), true},
		{"PrintableString and UTF8String", testName(t,
			[]testAttribute{{oidCountry, 19, "US"}},
			[]testAttribute{{oidOrg, 12, "Test Certificates 2011"}},
			[]testAttribute{{oidCommonName, 12, "Good CA"}}), true},
		{"different value", testName(t,
			[]testAttribute{{oidCountry, 19, "US"}},
			[]testAttribute{{oidOrg, 19, "Test Certificates 2011"}},
			[]testAttribute{{oidCommonName, 19, "Bad CA"}}), false},
		{"different RDN order", testName(t,
			[]testAttribute{{oidOrg, 19, "Test Certificates 2011"}},
			[]testAttribute{{oidCountry, 19, "US"}},
			[]testAttribute{{oidCommonName, 19, "Good CA"}}), false},
		{"missing RDN", testName(t,
			[]testAttribute{{oidCountry, 19, "US"}},
			[]testAttribute{{oidOrg, 19, "Test Certificates 2011"}}), false},
	}
	for _, test := range tests {
		if got := NamesMatch(base, test.other); got != test.want {
			t.Errorf("%s: NamesMatch = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestNamesMatchMultiValuedRDN(t *testing.T) {
	left := testName(t, []testAttribute{{oidCommonName, 19, "Alice"}, {oidOrg, 19, "Example"}})
	right := testName(t, []testAttribute{{oidOrg, 19, "EXAMPLE"}, {oidCommonName, 19, "alice"}})
	if !NamesMatch(left, right) {
		t.Fatal("multi-valued RDNs match attribute by attribute")
	}
	if NamesMatch(left, testName(t, []testAttribute{{oidCommonName, 19, "Alice"}})) {
		t.Fatal("an RDN with fewer attributes does not match")
	}
}

func TestNameWithinSubtree(t *testing.T) {
	subtree := testName(t, []testAttribute{{oidCountry, 19, "US"}}, []testAttribute{{oidOrg, 19, "Test Certificates 2011"}})
	inside := testName(t, []testAttribute{{oidCountry, 19, "US"}}, []testAttribute{{oidOrg, 19, "test certificates 2011"}}, []testAttribute{{oidCommonName, 19, "EE"}})
	outside := testName(t, []testAttribute{{oidCountry, 19, "US"}}, []testAttribute{{oidOrg, 19, "Other"}}, []testAttribute{{oidCommonName, 19, "EE"}})
	if !NameWithinSubtree(inside, subtree) || !NameWithinSubtree(subtree, subtree) {
		t.Fatal("names with the subtree as RDN prefix are within it")
	}
	if NameWithinSubtree(outside, subtree) || NameWithinSubtree(subtree, inside) {
		t.Fatal("names without the subtree prefix are outside it")
	}
	if !NameWithinSubtree(inside, EncodeSequence(nil)) {
		t.Fatal("an empty base contains every name")
	}
}
