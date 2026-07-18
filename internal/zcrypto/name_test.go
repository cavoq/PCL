package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"slices"
	"sort"
	"testing"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	zpkix "github.com/zmap/zcrypto/x509/pkix"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

func TestBuildNameProjectsLosslessRDNsAndAttributeCollections(t *testing.T) {
	firstCommonName := testNameAttributeDER(t, oid.AttributeCommonName, 12, []byte("first"))
	organization := testNameAttributeDER(t, oid.AttributeOrganizationName, 19, []byte("Example Org"))
	secondCommonName := testNameAttributeDER(t, oid.AttributeCommonName, 19, []byte("second"))
	unknown := testNameAttributeDER(t, "1.2.3.4", 4, []byte{0xaa, 0xbb})
	firstRDN := testNameRDN(firstCommonName, organization)
	secondRDN := testNameRDN(secondCommonName, unknown)
	rawName := internalasn1.EncodeSequence(append(append([]byte(nil), firstRDN...), secondRDN...))

	projected := BuildName("subject", rawName, zpkix.Name{CommonName: "display"})
	if malformed := projected.Children["malformed"]; malformed != nil {
		if _, err := internalasn1.ParseDistinguishedNameStrict(rawName); err != nil {
			t.Fatalf("test Name unexpectedly malformed: %v (DER %x)", err, rawName)
		}
		t.Fatal("BuildName marked a valid Name malformed")
	}
	if projected.Value != "CN=display" {
		t.Fatalf("display value = %v, want CN=display", projected.Value)
	}
	if got := projected.Children["raw"].Value.([]byte); !slices.Equal(got, rawName) {
		t.Fatalf("raw Name = %x, want %x", got, rawName)
	}

	rdns := node.CollectionElements(projected.Children["rdns"])
	if len(rdns) != 2 {
		t.Fatalf("RDN count = %d, want 2", len(rdns))
	}
	if got := rdns[0].Children["raw"].Value.([]byte); !slices.Equal(got, firstRDN) {
		t.Fatalf("first RDN raw = %x, want %x", got, firstRDN)
	}
	if got := len(node.CollectionElements(rdns[0].Children["attributes"])); got != 2 {
		t.Fatalf("first RDN attribute count = %d, want 2", got)
	}

	commonNames := projected.Children["commonName"]
	if commonNames == nil || commonNames != projected.Children[oid.AttributeCommonName] ||
		commonNames != projected.Children["attributes"].Children["commonName"] ||
		commonNames != projected.Children["attributes"].Children[oid.AttributeCommonName] {
		t.Fatal("friendly and OID paths do not alias the same commonName collection")
	}
	if commonNames.Value != "first" {
		t.Fatalf("legacy commonName value = %v, want first", commonNames.Value)
	}
	occurrences := node.CollectionElements(commonNames)
	if len(occurrences) != 2 {
		t.Fatalf("commonName occurrence count = %d, want 2", len(occurrences))
	}
	assertNameAttributeProjection(t, occurrences[0], "first", oid.AttributeCommonName, 12, "utf8String", firstCommonName)
	assertNameAttributeProjection(t, occurrences[1], "second", oid.AttributeCommonName, 19, "printableString", secondCommonName)

	unknownAttributes := projected.Children["1.2.3.4"]
	if unknownAttributes == nil {
		t.Fatal("unknown attribute OID was not projected")
	}
	unknownOccurrence := node.CollectionElements(unknownAttributes)[0]
	if _, known := unknownOccurrence.Children["name"]; known {
		t.Fatal("unknown attribute unexpectedly has a friendly name")
	}
	if got := unknownOccurrence.Children["value"].Value.([]byte); !bytes.Equal(got, []byte{0xaa, 0xbb}) {
		t.Fatalf("unknown value = %x", got)
	}
}

func TestBuildNameMarksMalformedRawName(t *testing.T) {
	projected := BuildName("issuer", []byte{0x30, 0x01, 0x00}, zpkix.Name{CommonName: "fallback"})
	if got := projected.Children["malformed"]; got == nil || got.Value != true {
		t.Fatalf("malformed marker = %#v", got)
	}
	if _, exists := projected.Children["attributes"]; exists {
		t.Fatal("malformed raw Name must not fall back to lossy parsed attributes")
	}
}

func TestBuildPkixNameFallbackProjectsAllExposedValues(t *testing.T) {
	projected := BuildPkixName("subject", zpkix.Name{
		CommonName:      "first",
		CommonNames:     []string{"first", "second"},
		SerialNumber:    "serial-one",
		SerialNumbers:   []string{"serial-one", "serial-two"},
		GivenName:       []string{"Ada"},
		Surname:         []string{"Lovelace"},
		EmailAddress:    []string{"ada@example.test"},
		DomainComponent: []string{"example", "test"},
		Names: []zpkix.AttributeTypeAndValue{
			{Type: zasn1.ObjectIdentifier{2, 5, 4, 3}, Value: "first"},
			{Type: zasn1.ObjectIdentifier{2, 5, 4, 15}, Value: "software"},
		},
	})

	for path, wantCount := range map[string]int{
		"commonName":       2,
		"serialNumber":     2,
		"givenName":        1,
		"surname":          1,
		"emailAddress":     1,
		"domainComponent":  2,
		"businessCategory": 1,
	} {
		collection := projected.Children[path]
		if collection == nil {
			t.Errorf("missing fallback collection %q", path)
			continue
		}
		if got := len(node.CollectionElements(collection)); got != wantCount {
			t.Errorf("%s occurrences = %d, want %d", path, got, wantCount)
		}
	}
}

func TestBuildPkixNameEmptyPreservesEmptyValueSemantics(t *testing.T) {
	projected := BuildPkixName("subject", zpkix.Name{})
	if projected.Value != "" {
		t.Fatalf("empty Name value = %#v, want empty string", projected.Value)
	}
	if got := len(node.CollectionElements(projected.Children["rdns"])); got != 0 {
		t.Fatalf("empty Name RDN count = %d", got)
	}
}

func assertNameAttributeProjection(
	t *testing.T,
	attribute *node.Node,
	wantValue string,
	wantOID string,
	wantTag int,
	wantEncoding string,
	wantRaw []byte,
) {
	t.Helper()
	if attribute.Value != wantValue || attribute.Children["value"].Value != wantValue {
		t.Errorf("value = %v / %v, want %q", attribute.Value, attribute.Children["value"].Value, wantValue)
	}
	if attribute.Children["oid"].Value != wantOID {
		t.Errorf("OID = %v, want %s", attribute.Children["oid"].Value, wantOID)
	}
	if attribute.Children["tag"].Value != wantTag || attribute.Children["encoding"].Value != wantTag {
		t.Errorf("tag/encoding = %v/%v, want %d", attribute.Children["tag"].Value, attribute.Children["encoding"].Value, wantTag)
	}
	if attribute.Children["encodingName"].Value != wantEncoding {
		t.Errorf("encodingName = %v, want %s", attribute.Children["encodingName"].Value, wantEncoding)
	}
	if got := attribute.Children["raw"].Value.([]byte); !slices.Equal(got, wantRaw) {
		t.Errorf("raw attribute = %x, want %x", got, wantRaw)
	}
}

func testNameAttributeDER(t *testing.T, identifier string, tag byte, content []byte) []byte {
	t.Helper()
	parsedOID, err := oid.Parse(identifier)
	if err != nil {
		t.Fatalf("parse OID %s: %v", identifier, err)
	}
	oidDER, err := stdasn1.Marshal(parsedOID)
	if err != nil {
		t.Fatalf("marshal OID %s: %v", identifier, err)
	}
	valueDER := encodeNameElement(tag, content)
	return internalasn1.EncodeSequence(append(oidDER, valueDER...))
}

func testNameRDN(attributes ...[]byte) []byte {
	sort.Slice(attributes, func(i, j int) bool { return bytes.Compare(attributes[i], attributes[j]) < 0 })
	var content []byte
	for _, attribute := range attributes {
		content = append(content, attribute...)
	}
	return encodeNameElement(byte(zasn1.TagSet|0x20), content)
}

func encodeNameElement(tag byte, content []byte) []byte {
	if len(content) >= 128 {
		panic("test DER helper only supports short lengths")
	}
	encoded := []byte{tag, byte(len(content))}
	return append(encoded, content...)
}
