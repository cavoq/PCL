package asn1

import (
	stdasn1 "encoding/asn1"
	"slices"
	"testing"
)

func TestParseDistinguishedNameStrictAllowsEmptyName(t *testing.T) {
	der := []byte{0x30, 0x00}
	name, err := ParseDistinguishedNameStrict(der)
	if err != nil {
		t.Fatalf("ParseDistinguishedNameStrict() error = %v", err)
	}
	if !slices.Equal(name.RawDER, der) {
		t.Fatalf("RawDER = %x, want %x", name.RawDER, der)
	}
	if len(name.RDNs) != 0 {
		t.Fatalf("len(RDNs) = %d, want 0", len(name.RDNs))
	}
}

func TestParseDistinguishedNameStrictPreservesRDNAndAttributeOrder(t *testing.T) {
	commonName := testNameAttribute(t, "2.5.4.3", 12, []byte("first"))
	organization := testNameAttribute(t, "2.5.4.10", 19, []byte("Example"))
	duplicateCommonName := testNameAttribute(t, "2.5.4.3", 12, []byte("second"))
	firstRDN := testNameRDN(commonName, organization)
	secondRDN := testNameRDN(duplicateCommonName)
	der := EncodeSequence(append(append([]byte(nil), firstRDN...), secondRDN...))

	name, err := ParseDistinguishedNameStrict(der)
	if err != nil {
		t.Fatalf("ParseDistinguishedNameStrict() error = %v", err)
	}
	if len(name.RDNs) != 2 {
		t.Fatalf("len(RDNs) = %d, want 2", len(name.RDNs))
	}
	if !slices.Equal(name.RDNs[0].RawDER, firstRDN) || !slices.Equal(name.RDNs[1].RawDER, secondRDN) {
		t.Fatalf("RDN encodings were not preserved")
	}

	firstAttributes := name.RDNs[0].Attributes
	if len(firstAttributes) != 2 {
		t.Fatalf("len(first RDN attributes) = %d, want 2", len(firstAttributes))
	}
	if firstAttributes[0].OID != "2.5.4.3" || firstAttributes[0].Value != "first" {
		t.Fatalf("first attribute = %+v", firstAttributes[0])
	}
	if firstAttributes[1].OID != "2.5.4.10" || firstAttributes[1].Value != "Example" {
		t.Fatalf("second attribute = %+v", firstAttributes[1])
	}
	if got := name.RDNs[1].Attributes[0]; got.OID != "2.5.4.3" || got.Value != "second" {
		t.Fatalf("duplicate attribute = %+v", got)
	}
	if !slices.Equal(firstAttributes[0].RawDER, commonName) {
		t.Fatalf("attribute RawDER = %x, want %x", firstAttributes[0].RawDER, commonName)
	}
}

func TestParseDistinguishedNameStrictDecodesCharacterStrings(t *testing.T) {
	tests := []struct {
		name     string
		tag      byte
		value    []byte
		encoding string
		want     string
	}{
		{name: "UTF8String", tag: 12, value: []byte("Grüße"), encoding: "utf8String", want: "Grüße"},
		{name: "PrintableString", tag: 19, value: []byte("Alice + Bob"), encoding: "printableString", want: "Alice + Bob"},
		{name: "IA5String", tag: 22, value: []byte("mail@example.test"), encoding: "ia5String", want: "mail@example.test"},
		{name: "VisibleString", tag: 26, value: []byte("Visible ~"), encoding: "visibleString", want: "Visible ~"},
		{name: "BMPString", tag: 30, value: []byte{0x00, 0x41, 0x03, 0xa9}, encoding: "bmpString", want: "AΩ"},
		{name: "UniversalString", tag: 28, value: []byte{0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0xf6, 0x00}, encoding: "universalString", want: "A😀"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attributeDER := testNameAttribute(t, "2.5.4.3", test.tag, test.value)
			name, err := ParseDistinguishedNameStrict(EncodeSequence(testNameRDN(attributeDER)))
			if err != nil {
				t.Fatalf("ParseDistinguishedNameStrict() error = %v", err)
			}

			attribute := name.RDNs[0].Attributes[0]
			if attribute.Tag != int(test.tag) || attribute.Encoding != test.encoding || attribute.Value != test.want {
				t.Fatalf("attribute = %+v, want tag %d, encoding %q, value %q", attribute, test.tag, test.encoding, test.want)
			}
			if !slices.Equal(attribute.RawValue, test.value) {
				t.Fatalf("RawValue = %x, want %x", attribute.RawValue, test.value)
			}
		})
	}
}

func TestParseDistinguishedNameStrictRetainsTeletexAndUnknownValues(t *testing.T) {
	tests := []struct {
		name     string
		tag      byte
		value    []byte
		encoding string
	}{
		{name: "TeletexString", tag: 20, value: []byte{0xc1, 0xe2}, encoding: "teletexString"},
		{name: "unknown OCTET STRING", tag: 4, value: []byte{0x00, 0xff}, encoding: "unknown"},
		{name: "unknown constructed SEQUENCE", tag: 0x30, value: []byte{0x05, 0x00}, encoding: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, err := ParseDistinguishedNameStrict(EncodeSequence(testNameRDN(testNameAttribute(t, "2.5.4.3", test.tag, test.value))))
			if err != nil {
				t.Fatalf("ParseDistinguishedNameStrict() error = %v", err)
			}
			attribute := name.RDNs[0].Attributes[0]
			wantValue := ""
			if test.tag == 20 {
				wantValue = "Áâ"
			}
			if attribute.Tag != int(test.tag) || attribute.Encoding != test.encoding || attribute.Value != wantValue {
				t.Fatalf("attribute = %+v", attribute)
			}
			if !slices.Equal(attribute.RawValue, test.value) {
				t.Fatalf("RawValue = %x, want %x", attribute.RawValue, test.value)
			}
		})
	}
}

func TestParseDistinguishedNameStrictRejectsMalformedNames(t *testing.T) {
	validAttribute := testNameAttribute(t, "2.5.4.3", 12, []byte("name"))
	oidDER, err := stdasn1.Marshal(stdasn1.ObjectIdentifier{2, 5, 4, 3})
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}

	tests := []struct {
		name string
		der  []byte
	}{
		{name: "missing name", der: nil},
		{name: "wrong outer tag", der: []byte{0x31, 0x00}},
		{name: "outer trailing data", der: append([]byte{0x30, 0x00}, 0x05, 0x00)},
		{name: "truncated RDN", der: []byte{0x30, 0x02, 0x31, 0x01}},
		{name: "non-SET name element", der: EncodeSequence(validAttribute)},
		{name: "non-SEQUENCE RDN element", der: EncodeSequence(testNameRDN([]byte{0x05, 0x00}))},
		{name: "attribute without OID", der: EncodeSequence(testNameRDN(EncodeSequence([]byte{0x0c, 0x01, 'x'})))},
		{name: "attribute without value", der: EncodeSequence(testNameRDN(EncodeSequence(oidDER)))},
		{name: "attribute trailing field", der: EncodeSequence(testNameRDN(EncodeSequence(append(append(append([]byte(nil), oidDER...), 0x0c, 0x01, 'x'), 0x05, 0x00))))},
		{name: "malformed value", der: EncodeSequence(testNameRDN(EncodeSequence(append(append([]byte(nil), oidDER...), 0x0c, 0x02, 'x'))))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseDistinguishedNameStrict(test.der); err == nil {
				t.Fatal("ParseDistinguishedNameStrict() error = nil, want error")
			}
		})
	}
}

func TestParseDistinguishedNameStrictRejectsEmptyRDN(t *testing.T) {
	if _, err := ParseDistinguishedNameStrict(EncodeSequence(testNameRDN())); err == nil {
		t.Fatal("ParseDistinguishedNameStrict() error = nil, want error")
	}
}

func TestParseDistinguishedNameStrictRejectsNonCanonicalRDNOrder(t *testing.T) {
	commonName := testNameAttribute(t, "2.5.4.3", 12, []byte("value"))
	organization := testNameAttribute(t, "2.5.4.10", 12, []byte("value"))
	if _, err := ParseDistinguishedNameStrict(EncodeSequence(testNameRDN(organization, commonName))); err == nil {
		t.Fatal("ParseDistinguishedNameStrict() error = nil, want DER SET ordering error")
	}
}

func TestParseDistinguishedNameStrictRejectsInvalidStringEncodings(t *testing.T) {
	tests := []struct {
		name  string
		tag   byte
		value []byte
	}{
		{name: "UTF8String", tag: 12, value: []byte{0xff}},
		{name: "PrintableString", tag: 19, value: []byte("not_valid")},
		{name: "IA5String", tag: 22, value: []byte{0x80}},
		{name: "VisibleString", tag: 26, value: []byte{'a', '\n'}},
		{name: "odd BMPString", tag: 30, value: []byte{0x00}},
		{name: "BMPString surrogate", tag: 30, value: []byte{0xd8, 0x00}},
		{name: "BMPString noncharacter range start", tag: 30, value: []byte{0xfd, 0xd0}},
		{name: "BMPString noncharacter range end", tag: 30, value: []byte{0xfd, 0xef}},
		{name: "BMPString noncharacter FFFE", tag: 30, value: []byte{0xff, 0xfe}},
		{name: "BMPString noncharacter FFFF", tag: 30, value: []byte{0xff, 0xff}},
		{name: "short UniversalString", tag: 28, value: []byte{0x00, 0x00, 0x00}},
		{name: "invalid UniversalString code point", tag: 28, value: []byte{0x00, 0x11, 0x00, 0x00}},
		{name: "overflowing UniversalString code point", tag: 28, value: []byte{0xff, 0xff, 0xff, 0xff}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der := EncodeSequence(testNameRDN(testNameAttribute(t, "2.5.4.3", test.tag, test.value)))
			if _, err := ParseDistinguishedNameStrict(der); err == nil {
				t.Fatal("ParseDistinguishedNameStrict() error = nil, want error")
			}
		})
	}
}

func TestParseDistinguishedNameStrictRejectsConstructedStringEncodings(t *testing.T) {
	for _, tag := range []byte{12, 19, 20, 22, 26, 28, 30} {
		t.Run(StringTypeName(int(tag)), func(t *testing.T) {
			constructedTag := tag | 0x20
			value := encodeTagged(tag, []byte("value"))
			der := EncodeSequence(testNameRDN(testNameAttribute(t, "2.5.4.3", constructedTag, value)))
			if _, err := ParseDistinguishedNameStrict(der); err == nil {
				t.Fatal("ParseDistinguishedNameStrict() error = nil, want constructed string error")
			}
		})
	}
}

func TestParseDistinguishedNameStrictOwnsReturnedBytes(t *testing.T) {
	value := []byte("Alice")
	attributeDER := testNameAttribute(t, "2.5.4.3", 12, value)
	der := EncodeSequence(testNameRDN(attributeDER))
	originalDER := slices.Clone(der)

	name, err := ParseDistinguishedNameStrict(der)
	if err != nil {
		t.Fatalf("ParseDistinguishedNameStrict() error = %v", err)
	}
	attribute := &name.RDNs[0].Attributes[0]
	originalRDN := slices.Clone(name.RDNs[0].RawDER)
	originalAttribute := slices.Clone(attribute.RawDER)
	originalValue := slices.Clone(attribute.RawValue)

	for index := range der {
		der[index] ^= 0xff
	}
	if !slices.Equal(name.RawDER, originalDER) || !slices.Equal(name.RDNs[0].RawDER, originalRDN) ||
		!slices.Equal(attribute.RawDER, originalAttribute) || !slices.Equal(attribute.RawValue, originalValue) {
		t.Fatal("mutating the input changed returned data")
	}

	name.RawDER[0] ^= 0xff
	if !slices.Equal(name.RDNs[0].RawDER, originalRDN) || !slices.Equal(attribute.RawDER, originalAttribute) || !slices.Equal(attribute.RawValue, originalValue) {
		t.Fatal("RawDER fields alias nested data")
	}
	name.RDNs[0].RawDER[0] ^= 0xff
	if !slices.Equal(attribute.RawDER, originalAttribute) || !slices.Equal(attribute.RawValue, originalValue) {
		t.Fatal("RDN RawDER aliases attribute data")
	}
	attribute.RawDER[0] ^= 0xff
	if !slices.Equal(attribute.RawValue, originalValue) {
		t.Fatal("attribute RawDER aliases RawValue")
	}
}

func testNameAttribute(t *testing.T, oid string, tag byte, value []byte) []byte {
	t.Helper()
	var parsedOID stdasn1.ObjectIdentifier
	switch oid {
	case "2.5.4.3":
		parsedOID = stdasn1.ObjectIdentifier{2, 5, 4, 3}
	case "2.5.4.10":
		parsedOID = stdasn1.ObjectIdentifier{2, 5, 4, 10}
	default:
		t.Fatalf("test OID %q is not defined", oid)
	}
	objectIdentifier, err := stdasn1.Marshal(parsedOID)
	if err != nil {
		t.Fatalf("marshal OID %q: %v", oid, err)
	}
	contents := append(append([]byte(nil), objectIdentifier...), encodeTagged(tag, value)...)
	return EncodeSequence(contents)
}

func testNameRDN(attributes ...[]byte) []byte {
	var contents []byte
	for _, attribute := range attributes {
		contents = append(contents, attribute...)
	}
	return encodeTagged(0x31, contents)
}
