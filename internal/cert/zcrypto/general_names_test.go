package zcrypto

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseGeneralNamesPreservesEntriesAndOwnsRawBytes(t *testing.T) {
	values := []testGeneralName{
		{tag: 2, value: []byte("first.example.test")},
		{tag: 1, value: []byte("user@example.test")},
		{tag: 2, value: []byte("second.example.test")},
		{tag: 6, value: []byte("https://example.test/path")},
	}
	der := buildTestGeneralNames(values)
	parsed, err := parseGeneralNames(der)
	if err != nil {
		t.Fatalf("parse GeneralNames: %v", err)
	}
	if len(parsed) != len(values) {
		t.Fatalf("parsed %d names, want %d", len(parsed), len(values))
	}

	for index, want := range values {
		got := parsed[index]
		if got.Tag != want.tag || !bytes.Equal(got.RawValue, want.value) || len(got.RawDER) == 0 {
			t.Fatalf("name %d = %+v, want tag %d and value %x", index, got, want.tag, want.value)
		}
	}

	wantRaw := append([]byte(nil), parsed[1].RawDER...)
	wantValue := append([]byte(nil), parsed[1].RawValue...)
	for index := range der {
		der[index] = 0
	}
	if !bytes.Equal(parsed[1].RawDER, wantRaw) || !bytes.Equal(parsed[1].RawValue, wantValue) {
		t.Fatal("parsed GeneralName aliases the extension input")
	}
}

func TestBuildParsedGeneralNamePreservesScalarAndEncodingMetadata(t *testing.T) {
	rawValue := []byte{'n', 'o', 'n', 0xe9, 'a', 's', 'c', 'i', 'i'}
	parsed := parsedGeneralName{
		Tag:      2,
		RawDER:   append([]byte{0x82, byte(len(rawValue))}, rawValue...),
		RawValue: rawValue,
	}
	built := buildParsedGeneralName("0", parsed)

	if got, ok := built.Value.(string); !ok || got != string(rawValue) {
		t.Fatalf("scalar value = %#v, want exact raw string %q", built.Value, string(rawValue))
	}
	if got := built.Children["tag"]; got == nil || got.Value != 2 {
		t.Fatalf("tag metadata = %#v, want 2", got)
	}
	if got := built.Children["raw"]; got == nil || !bytes.Equal(got.Value.([]byte), parsed.RawDER) {
		t.Fatalf("raw metadata = %#v, want %x", got, parsed.RawDER)
	}
	if got := built.Children["rawValue"]; got == nil || !bytes.Equal(got.Value.([]byte), rawValue) {
		t.Fatalf("rawValue metadata = %#v, want %x", got, rawValue)
	}
}

func TestBuildParsedEDIPartyNameProjectsValidatedDirectoryStrings(t *testing.T) {
	der := buildTestEDIPartyGeneralNames("Earth", "Party")
	parsed, err := parseGeneralNames(der)
	if err != nil {
		t.Fatalf("parse ediPartyName: %v", err)
	}
	built := buildParsedGeneralName("0", parsed[0])
	for child, want := range map[string]string{
		"nameAssigner": "Earth",
		"partyName":    "Party",
	} {
		got := built.Children[child]
		if got == nil || got.Value != want || got.Children["encoding"] == nil ||
			got.Children["raw"] == nil || got.Children["rawValue"] == nil {
			t.Fatalf("%s = %#v, want validated DirectoryString %q", child, got, want)
		}
	}
}

func TestParseGeneralNamesRejectsInvalidNames(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "empty GeneralNames", value: []byte{0x30, 0x00}},
		{name: "unknown choice", value: []byte{0x30, 0x02, 0x89, 0x00}},
		{name: "wrong class", value: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{name: "empty DNS name", value: []byte{0x30, 0x02, 0x82, 0x00}},
		{name: "non-IA5 email", value: buildTestGeneralNames([]testGeneralName{{tag: 1, value: []byte{0xff}}})},
		{name: "non-IA5 DNS name", value: buildTestGeneralNames([]testGeneralName{{tag: 2, value: []byte{0xff}}})},
		{name: "non-IA5 URI", value: buildTestGeneralNames([]testGeneralName{{tag: 6, value: []byte{0xff}}})},
		{name: "empty x400 address", value: []byte{0x30, 0x02, 0xa3, 0x00}},
		{name: "invalid IP length", value: []byte{0x30, 0x05, 0x87, 0x03, 0x01, 0x02, 0x03}},
		{
			name:  "otherName value is not DER",
			value: []byte{0x30, 0x08, 0xa0, 0x06, 0x06, 0x01, 0x2a, 0xa0, 0x01, 0xff},
		},
		{
			name: "otherName value has two elements",
			value: []byte{
				0x30, 0x0d, 0xa0, 0x0b, 0x06, 0x01, 0x2a,
				0xa0, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
			},
		},
		{
			name:  "ediPartyName partyName is not DirectoryString DER",
			value: []byte{0x30, 0x05, 0xa5, 0x03, 0xa1, 0x01, 0xff},
		},
		{
			name: "ediPartyName nameAssigner is not DirectoryString DER",
			value: []byte{
				0x30, 0x0a, 0xa5, 0x08,
				0xa0, 0x01, 0xff,
				0xa1, 0x03, 0x0c, 0x01, 'A',
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseGeneralNames(test.value); err == nil {
				t.Fatal("expected invalid GeneralName to be rejected")
			}
		})
	}
}

func buildTestEDIPartyGeneralNames(nameAssigner, partyName string) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(names *cryptobyte.Builder) {
		names.AddASN1(cryptobyte_asn1.Tag(5).Constructed().ContextSpecific(), func(edi *cryptobyte.Builder) {
			if nameAssigner != "" {
				edi.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(value *cryptobyte.Builder) {
					value.AddASN1(cryptobyte_asn1.UTF8String, func(text *cryptobyte.Builder) {
						text.AddBytes([]byte(nameAssigner))
					})
				})
			}
			edi.AddASN1(cryptobyte_asn1.Tag(1).Constructed().ContextSpecific(), func(value *cryptobyte.Builder) {
				value.AddASN1(cryptobyte_asn1.PrintableString, func(text *cryptobyte.Builder) {
					text.AddBytes([]byte(partyName))
				})
			})
		})
	})
	return builder.BytesOrPanic()
}

type testGeneralName struct {
	tag         int
	constructed bool
	value       []byte
}

func buildTestGeneralNames(names []testGeneralName) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, name := range names {
			tag := cryptobyte_asn1.Tag(name.tag).ContextSpecific()
			if name.constructed {
				tag = tag.Constructed()
			}
			sequence.AddASN1(tag, func(value *cryptobyte.Builder) {
				value.AddBytes(name.value)
			})
		}
	})
	return builder.BytesOrPanic()
}
