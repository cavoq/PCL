package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestPolicyMappingsStrictPreservesEveryPairAndAnyPolicy(t *testing.T) {
	der := buildPolicyMappingsValue(
		[2]stdasn1.ObjectIdentifier{
			{2, 5, 29, 32, 0},
			{1, 2, 3, 4},
		},
		[2]stdasn1.ObjectIdentifier{
			{1, 2, 3, 5},
			{2, 5, 29, 32, 0},
		},
	)

	mappings, err := DecodePolicyMappingsStrict(der)
	if err != nil {
		t.Fatalf("DecodePolicyMappingsStrict() error = %v", err)
	}
	if len(mappings) != 2 ||
		mappings[0].IssuerDomainPolicy != "2.5.29.32.0" ||
		mappings[0].SubjectDomainPolicy != "1.2.3.4" ||
		mappings[1].SubjectDomainPolicy != "2.5.29.32.0" {
		t.Fatalf("mappings = %#v", mappings)
	}

	n, err := ParsePolicyMappingsStrict(der)
	if err != nil {
		t.Fatalf("ParsePolicyMappingsStrict() error = %v", err)
	}
	assertExtensionSchemaValue(t, n, "count", 2)
	first := n.Children["mappings"].Children["0"]
	assertExtensionSchemaValue(t, first, "issuerDomainPolicy", "2.5.29.32.0")
	assertExtensionSchemaValue(t, first, "subjectDomainPolicy", "1.2.3.4")
	assertExtensionSchemaBytes(t, first.Children["raw"].Value, mappings[0].RawDER)
	assertExtensionSchemaBytes(t, n.Children["raw"].Value, der)

	wantRaw := append([]byte(nil), mappings[0].RawDER...)
	for index := range der {
		der[index] = 0
	}
	if !bytes.Equal(mappings[0].RawDER, wantRaw) {
		t.Fatal("typed PolicyMapping raw DER aliases input")
	}
}

func TestPolicyMappingsStrictRejectsMalformedDER(t *testing.T) {
	oneOIDMapping := wrapDERSequence(derObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 3}))
	threeOIDMapping := wrapDERSequence(
		append(
			append(derObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 3}), derObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 4})...),
			derObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 5})...,
		),
	)
	valid := buildPolicyMappingsValue([2]stdasn1.ObjectIdentifier{{1, 2, 3}, {1, 2, 4}})
	tests := map[string][]byte{
		"empty sequence":        {0x30, 0x00},
		"mapping has one OID":   wrapDERSequence(oneOIDMapping),
		"mapping has extra OID": wrapDERSequence(threeOIDMapping),
		"wrong mapping tag":     {0x30, 0x03, 0x02, 0x01, 0x00},
		"trailing DER":          append(valid, 0),
	}

	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicyMappingsStrict(der); err == nil {
				t.Fatal("DecodePolicyMappingsStrict() error = nil, want error")
			}
			assertExtensionSchemaValue(t, ParsePolicyMappings(der), "malformed", true)
		})
	}
}

func TestPolicyConstraintsStrictPreservesZeroAndFieldPresence(t *testing.T) {
	der := buildPolicyConstraintsValue([]byte{0x00}, []byte{0x00, 0xff})
	facts, err := DecodePolicyConstraintsStrict(der)
	if err != nil {
		t.Fatalf("DecodePolicyConstraintsStrict() error = %v", err)
	}
	if !facts.RequireExplicitPolicyPresent || facts.RequireExplicitPolicy != 0 ||
		!facts.InhibitPolicyMappingPresent || facts.InhibitPolicyMapping != 255 {
		t.Fatalf("policy constraints = %#v", facts)
	}

	n, err := ParsePolicyConstraintsStrict(der)
	if err != nil {
		t.Fatalf("ParsePolicyConstraintsStrict() error = %v", err)
	}
	assertExtensionSchemaValue(t, n, "requireExplicitPolicyPresent", true)
	assertExtensionSchemaValue(t, n, "inhibitPolicyMappingPresent", true)
	if got := n.Children["requireExplicitPolicy"].Value; got != 0 {
		t.Fatalf("requireExplicitPolicy = %#v, want 0", got)
	}
	if got := n.Children["inhibitPolicyMapping"].Value; got != 255 {
		t.Fatalf("inhibitPolicyMapping = %#v, want 255", got)
	}
	assertExtensionSchemaBytes(t, n.Children["raw"].Value, der)
}

func TestPolicyConstraintsStrictPreservesSingleOptionalField(t *testing.T) {
	tests := []struct {
		name           string
		der            []byte
		requirePresent bool
		inhibitPresent bool
	}{
		{
			name:           "require explicit policy only",
			der:            buildPolicyConstraintsValue([]byte{0x02}, nil),
			requirePresent: true,
		},
		{
			name:           "inhibit mapping only",
			der:            buildPolicyConstraintsValue(nil, []byte{0x03}),
			inhibitPresent: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts, err := DecodePolicyConstraintsStrict(test.der)
			if err != nil {
				t.Fatalf("DecodePolicyConstraintsStrict() error = %v", err)
			}
			if facts.RequireExplicitPolicyPresent != test.requirePresent ||
				facts.InhibitPolicyMappingPresent != test.inhibitPresent {
				t.Fatalf("presence facts = %#v", facts)
			}
		})
	}
}

func TestPolicyConstraintsStrictRejectsMalformedDER(t *testing.T) {
	valid := buildPolicyConstraintsValue([]byte{0x00}, nil)
	tests := map[string][]byte{
		"empty":                  {0x30, 0x00},
		"negative":               buildPolicyConstraintsValue([]byte{0xff}, nil),
		"redundant leading zero": buildPolicyConstraintsValue([]byte{0x00, 0x01}, nil),
		"out of order":           buildPolicyConstraintsFields([]taggedInteger{{tag: 1, content: []byte{0}}, {tag: 0, content: []byte{0}}}),
		"duplicate":              buildPolicyConstraintsFields([]taggedInteger{{tag: 0, content: []byte{0}}, {tag: 0, content: []byte{1}}}),
		"trailing DER":           append(valid, 0),
	}

	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicyConstraintsStrict(der); err == nil {
				t.Fatal("DecodePolicyConstraintsStrict() error = nil, want error")
			}
			assertExtensionSchemaValue(t, ParsePolicyConstraints(der), "malformed", true)
		})
	}
}

func TestInhibitAnyPolicyStrictPreservesBoundaryValues(t *testing.T) {
	for _, test := range []struct {
		name string
		der  []byte
		want int
	}{
		{name: "zero", der: []byte{0x02, 0x01, 0x00}},
		{name: "positive with sign octet", der: []byte{0x02, 0x02, 0x00, 0xff}, want: 255},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeInhibitAnyPolicyStrict(test.der)
			if err != nil {
				t.Fatalf("DecodeInhibitAnyPolicyStrict() error = %v", err)
			}
			if !got.FitsInt || got.Int != test.want {
				t.Fatalf("DecodeInhibitAnyPolicyStrict() = %#v, want %d", got, test.want)
			}
			n, err := ParseInhibitAnyPolicyStrict(test.der)
			if err != nil {
				t.Fatalf("ParseInhibitAnyPolicyStrict() error = %v", err)
			}
			if n.Value != test.want {
				t.Fatalf("inhibitAnyPolicy value = %#v, want %d", n.Value, test.want)
			}
			if got := n.Children["skipCerts"].Value; got != test.want {
				t.Fatalf("skipCerts = %#v, want %d", got, test.want)
			}
			assertExtensionSchemaBytes(t, n.Children["raw"].Value, test.der)
		})
	}
}

func TestInhibitAnyPolicyStrictRejectsMalformedDER(t *testing.T) {
	tests := map[string][]byte{
		"negative":               {0x02, 0x01, 0xff},
		"redundant leading zero": {0x02, 0x02, 0x00, 0x01},
		"wrong tag":              {0x0a, 0x01, 0x00},
		"trailing DER":           {0x02, 0x01, 0x00, 0x00},
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeInhibitAnyPolicyStrict(der); err == nil {
				t.Fatal("DecodeInhibitAnyPolicyStrict() error = nil, want error")
			}
			assertExtensionSchemaValue(t, ParseInhibitAnyPolicy(der), "malformed", true)
		})
	}
}

func buildPolicyMappingsValue(mappings ...[2]stdasn1.ObjectIdentifier) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, mapping := range mappings {
			sequence.AddASN1(cryptobyte_asn1.SEQUENCE, func(pair *cryptobyte.Builder) {
				pair.AddASN1ObjectIdentifier(mapping[0])
				pair.AddASN1ObjectIdentifier(mapping[1])
			})
		}
	})
	return builder.BytesOrPanic()
}

func derObjectIdentifier(identifier stdasn1.ObjectIdentifier) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1ObjectIdentifier(identifier)
	return builder.BytesOrPanic()
}

func wrapDERSequence(contents []byte) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		sequence.AddBytes(contents)
	})
	return builder.BytesOrPanic()
}

type taggedInteger struct {
	tag     int
	content []byte
}

func buildPolicyConstraintsValue(requireExplicit, inhibitMapping []byte) []byte {
	var fields []taggedInteger
	if requireExplicit != nil {
		fields = append(fields, taggedInteger{tag: 0, content: requireExplicit})
	}
	if inhibitMapping != nil {
		fields = append(fields, taggedInteger{tag: 1, content: inhibitMapping})
	}
	return buildPolicyConstraintsFields(fields)
}

func buildPolicyConstraintsFields(fields []taggedInteger) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, field := range fields {
			sequence.AddASN1(cryptobyte_asn1.Tag(field.tag).ContextSpecific(), func(value *cryptobyte.Builder) {
				value.AddBytes(field.content)
			})
		}
	})
	return builder.BytesOrPanic()
}
