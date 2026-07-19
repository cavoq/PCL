package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"strconv"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestNameConstraintsStrictProjectsAllGeneralNameFormsLosslessly(t *testing.T) {
	names := allNameConstraintGeneralNames()
	der := buildNameConstraintsValue(names, nil)

	facts, err := DecodeNameConstraintsStrict(der)
	if err != nil {
		t.Fatalf("DecodeNameConstraintsStrict() error = %v", err)
	}
	if len(facts.PermittedSubtrees) != 9 || len(facts.ExcludedSubtrees) != 0 {
		t.Fatalf("NameConstraints facts = %#v", facts)
	}
	if !bytes.Equal(facts.RawDER, der) {
		t.Fatalf("raw DER = %x, want %x", facts.RawDER, der)
	}
	for tag, subtree := range facts.PermittedSubtrees {
		if subtree.BaseTag != tag || len(subtree.BaseRawDER) == 0 || len(subtree.RawDER) == 0 {
			t.Fatalf("subtree %d facts = %#v", tag, subtree)
		}
		if subtree.MinimumPresent || subtree.MaximumPresent {
			t.Fatalf("subtree %d unexpectedly has min/max: %#v", tag, subtree)
		}
	}

	n, err := ParseNameConstraintsStrict(der)
	if err != nil {
		t.Fatalf("ParseNameConstraintsStrict() error = %v", err)
	}
	assertExtensionSchemaValue(t, n, "unprocessed", true)
	permitted := n.Children["permittedSubtrees"]
	assertExtensionSchemaValue(t, permitted, "count", 9)
	for tag := 0; tag <= 8; tag++ {
		entry := permitted.Children[strconv.Itoa(tag)]
		if entry == nil {
			t.Fatalf("missing ordered subtree %d", tag)
		}
		assertExtensionSchemaValue(t, entry, "tag", tag)
		assertExtensionSchemaValue(t, entry, "type", generalNameType(tag))
		if permitted.Children[generalNameType(tag)] == nil {
			t.Fatalf("missing %s compatibility collection", generalNameType(tag))
		}
		assertExtensionSchemaValue(t, entry, "minimumPresent", false)
		assertExtensionSchemaValue(t, entry, "maximumPresent", false)
	}
	assertExtensionSchemaValue(t, permitted.Children["iPAddress"].Children["0"].Children["base"], "prefixLength", 24)
	assertExtensionSchemaValue(t, permitted.Children["registeredID"].Children["0"], "value", "1.2.3")
	directoryName := permitted.Children["directoryName"].Children["0"].Children["base"].Children["directoryName"]
	if commonName := directoryName.Children["commonName"]; commonName == nil || commonName.Value != "constraint" {
		t.Fatalf("directoryName commonName = %#v, want constraint", commonName)
	}
	assertExtensionSchemaBytes(t, n.Children["raw"].Value, der)

	wantBaseRaw := append([]byte(nil), facts.PermittedSubtrees[0].BaseRawDER...)
	for index := range der {
		der[index] = 0
	}
	if !bytes.Equal(facts.PermittedSubtrees[0].BaseRawDER, wantBaseRaw) {
		t.Fatal("typed NameConstraints facts alias input")
	}
}

func TestNameConstraintsStrictPreservesNonDefaultMinimumAndMaximumPresence(t *testing.T) {
	minimum, maximum := 1, 0
	permitted := []constraintSubtree{{
		name:    constraintGeneralName{tag: 2, content: []byte("example.test")},
		minimum: &minimum,
		maximum: &maximum,
	}}
	der := buildNameConstraintsValue(permitted, nil)

	facts, err := DecodeNameConstraintsStrict(der)
	if err != nil {
		t.Fatalf("DecodeNameConstraintsStrict() error = %v", err)
	}
	subtree := facts.PermittedSubtrees[0]
	if !subtree.MinimumPresent || subtree.Minimum != 1 ||
		!subtree.MaximumPresent || subtree.Maximum != 0 {
		t.Fatalf("subtree facts = %#v", subtree)
	}

	n, err := ParseNameConstraintsStrict(der)
	if err != nil {
		t.Fatalf("ParseNameConstraintsStrict() error = %v", err)
	}
	if n.Children["unprocessed"] != nil {
		t.Fatal("supported dNSName constraint was marked unprocessed")
	}
	projected := n.Children["permittedSubtrees"].Children["0"]
	assertExtensionSchemaValue(t, projected, "minimumPresent", true)
	assertExtensionSchemaValue(t, projected, "maximumPresent", true)
	if projected.Children["min"].Value != 1 || projected.Children["max"].Value != 0 {
		t.Fatalf("min/max projection = %#v / %#v", projected.Children["min"], projected.Children["max"])
	}
}

func TestNameConstraintsStrictRejectsMalformedAndNonCanonicalDER(t *testing.T) {
	zero := 0
	validName := constraintGeneralName{tag: 2, content: []byte("example.test")}
	valid := buildNameConstraintsValue([]constraintSubtree{{name: validName}}, nil)
	invalidMask := constraintGeneralName{
		tag:     7,
		content: []byte{192, 0, 2, 0, 255, 0, 255, 0},
	}
	ipAddressNotConstraint := constraintGeneralName{tag: 7, content: []byte{192, 0, 2, 1}}
	tests := map[string][]byte{
		"empty sequence":             {0x30, 0x00},
		"empty permitted subtrees":   {0x30, 0x02, 0xa0, 0x00},
		"empty general subtree":      {0x30, 0x04, 0xa0, 0x02, 0x30, 0x00},
		"explicit DEFAULT minimum":   buildNameConstraintsValue([]constraintSubtree{{name: validName, minimum: &zero}}, nil),
		"noncontiguous IP mask":      buildNameConstraintsValue([]constraintSubtree{{name: invalidMask}}, nil),
		"ordinary IP address length": buildNameConstraintsValue([]constraintSubtree{{name: ipAddressNotConstraint}}, nil),
		"non-IA5 rfc822Name":         buildNameConstraintsValue([]constraintSubtree{{name: constraintGeneralName{tag: 1, content: []byte{0xff}}}}, nil),
		"non-IA5 dNSName":            buildNameConstraintsValue([]constraintSubtree{{name: constraintGeneralName{tag: 2, content: []byte{0xff}}}}, nil),
		"non-IA5 URI":                buildNameConstraintsValue([]constraintSubtree{{name: constraintGeneralName{tag: 6, content: []byte{0xff}}}}, nil),
		"duplicate permitted field":  buildRawNameConstraintsFields([]constraintField{{tag: 0, subtrees: []constraintSubtree{{name: validName}}}, {tag: 0, subtrees: []constraintSubtree{{name: validName}}}}),
		"fields out of order":        buildRawNameConstraintsFields([]constraintField{{tag: 1, subtrees: []constraintSubtree{{name: validName}}}, {tag: 0, subtrees: []constraintSubtree{{name: validName}}}}),
		"trailing DER":               append(valid, 0),
	}

	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNameConstraintsStrict(der); err == nil {
				t.Fatal("ParseNameConstraintsStrict() error = nil, want error")
			}
			compat := ParseNameConstraints(der)
			assertExtensionSchemaValue(t, compat, "malformed", true)
			assertExtensionSchemaBytes(t, compat.Children["raw"].Value, der)
		})
	}
}

type constraintGeneralName struct {
	tag         int
	constructed bool
	content     []byte
}

type constraintSubtree struct {
	name    constraintGeneralName
	minimum *int
	maximum *int
}

type constraintField struct {
	tag      int
	subtrees []constraintSubtree
}

func allNameConstraintGeneralNames() []constraintSubtree {
	return []constraintSubtree{
		{name: constraintGeneralName{tag: 0, constructed: true, content: otherNameConstraintContent()}},
		{name: constraintGeneralName{tag: 1, content: []byte("mail@example.test")}},
		{name: constraintGeneralName{tag: 2, content: []byte("example.test")}},
		{name: constraintGeneralName{tag: 3, constructed: true, content: x400ConstraintContent()}},
		{name: constraintGeneralName{tag: 4, constructed: true, content: directoryNameConstraintContent()}},
		{name: constraintGeneralName{tag: 5, constructed: true, content: ediPartyConstraintContent()}},
		{name: constraintGeneralName{tag: 6, content: []byte("example.test")}},
		{name: constraintGeneralName{tag: 7, content: []byte{192, 0, 2, 0, 255, 255, 255, 0}}},
		{name: constraintGeneralName{tag: 8, content: []byte{0x2a, 0x03}}},
	}
}

func buildNameConstraintsValue(permitted, excluded []constraintSubtree) []byte {
	var fields []constraintField
	if permitted != nil {
		fields = append(fields, constraintField{tag: 0, subtrees: permitted})
	}
	if excluded != nil {
		fields = append(fields, constraintField{tag: 1, subtrees: excluded})
	}
	return buildRawNameConstraintsFields(fields)
}

func buildRawNameConstraintsFields(fields []constraintField) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, field := range fields {
			sequence.AddASN1(cryptobyte_asn1.Tag(field.tag).ContextSpecific().Constructed(), func(subtrees *cryptobyte.Builder) {
				for _, subtree := range field.subtrees {
					addConstraintSubtree(subtrees, subtree)
				}
			})
		}
	})
	return builder.BytesOrPanic()
}

func addConstraintSubtree(builder *cryptobyte.Builder, subtree constraintSubtree) {
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		tag := cryptobyte_asn1.Tag(subtree.name.tag).ContextSpecific()
		if subtree.name.constructed {
			tag = tag.Constructed()
		}
		sequence.AddASN1(tag, func(value *cryptobyte.Builder) {
			value.AddBytes(subtree.name.content)
		})
		if subtree.minimum != nil {
			addConstraintDistance(sequence, 0, *subtree.minimum)
		}
		if subtree.maximum != nil {
			addConstraintDistance(sequence, 1, *subtree.maximum)
		}
	})
}

func addConstraintDistance(builder *cryptobyte.Builder, tag, value int) {
	builder.AddASN1(cryptobyte_asn1.Tag(tag).ContextSpecific(), func(integer *cryptobyte.Builder) {
		integer.AddBytes([]byte{byte(value)})
	})
}

func otherNameConstraintContent() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 3, 4})
	builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(value *cryptobyte.Builder) {
		value.AddASN1Int64(7)
	})
	return builder.BytesOrPanic()
}

func x400ConstraintContent() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		sequence.AddASN1(cryptobyte_asn1.Tag(3).ContextSpecific(), func(value *cryptobyte.Builder) {
			value.AddBytes([]byte("Org"))
		})
	})
	return builder.BytesOrPanic()
}

func directoryNameConstraintContent() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(name *cryptobyte.Builder) {
		name.AddASN1(cryptobyte_asn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cryptobyte_asn1.SEQUENCE, func(attribute *cryptobyte.Builder) {
				attribute.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 5, 4, 3})
				attribute.AddASN1(cryptobyte_asn1.UTF8String, func(value *cryptobyte.Builder) {
					value.AddBytes([]byte("constraint"))
				})
			})
		})
	})
	return builder.BytesOrPanic()
}

func ediPartyConstraintContent() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(party *cryptobyte.Builder) {
		party.AddASN1(cryptobyte_asn1.PrintableString, func(value *cryptobyte.Builder) {
			value.AddBytes([]byte("Party"))
		})
	})
	return builder.BytesOrPanic()
}
