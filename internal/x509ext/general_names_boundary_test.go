package x509ext

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type boundaryGeneralName struct {
	tag         int
	constructed bool
	content     []byte
}

func TestDecodeGeneralNamesCoversEveryChoice(t *testing.T) {
	namesDER := buildBoundaryGeneralNames([]boundaryGeneralName{
		{tag: 0, constructed: true, content: boundaryOtherNameContent()},
		{tag: 1, content: []byte("mail@example.test")},
		{tag: 2, content: []byte("www.example.test")},
		{tag: 3, constructed: true, content: boundaryX400Content()},
		{tag: 4, constructed: true, content: boundaryDirectoryNameDER("directory")},
		{tag: 5, constructed: true, content: boundaryEDIPartyContent()},
		{tag: 6, content: []byte("https://example.test/path")},
		{tag: 7, content: []byte{192, 0, 2, 1}},
		{tag: 8, content: []byte{0x2a, 0x03}},
	})
	names, err := DecodeGeneralNames(namesDER)
	if err != nil {
		t.Fatalf("DecodeGeneralNames() error = %v", err)
	}
	if len(names) != 9 {
		t.Fatalf("DecodeGeneralNames() returned %d names, want 9", len(names))
	}
	for tag, name := range names {
		if name.Tag != tag || GeneralNameType(tag) == "unknown" || len(name.RawDER) == 0 || len(name.RawValue) == 0 {
			t.Errorf("GeneralName %d = %#v", tag, name)
		}
	}
	if names[0].OtherName == nil || names[0].OtherName.TypeID != "1.2.3.4" {
		t.Fatalf("otherName = %#v", names[0].OtherName)
	}
	if names[5].EDIPartyName == nil || names[5].EDIPartyName.NameAssigner == nil ||
		names[5].EDIPartyName.NameAssigner.Value != "Earth" ||
		names[5].EDIPartyName.PartyName.Value != "Party" {
		t.Fatalf("ediPartyName = %#v", names[5].EDIPartyName)
	}
	if got := names[7].IPString(); got != "192.0.2.1" {
		t.Fatalf("IPString() = %q", got)
	}
	if got := names[6].IPString(); got != "" {
		t.Fatalf("IPString() for URI = %q", got)
	}
	registeredID, err := DecodeRegisteredID(names[8].RawDER)
	if err != nil || registeredID != "1.2.3" {
		t.Fatalf("DecodeRegisteredID() = %q, %v", registeredID, err)
	}
	if GeneralNameType(99) != "unknown" {
		t.Fatal("unknown GeneralName tag was assigned a known name")
	}
}

func TestDecodeGeneralNamesRejectsMalformedForms(t *testing.T) {
	malformed := map[string][]byte{
		"absent value":            nil,
		"empty sequence":          {0x30, 0x00},
		"trailing DER":            {0x30, 0x03, 0x82, 0x01, 'x', 0x00},
		"unknown choice":          {0x30, 0x03, 0x89, 0x01, 'x'},
		"wrong class":             {0x30, 0x03, 0x02, 0x01, 0x01},
		"empty name":              {0x30, 0x02, 0x82, 0x00},
		"constructed DNS":         {0x30, 0x03, 0xa2, 0x01, 'x'},
		"primitive directory":     {0x30, 0x03, 0x84, 0x01, 'x'},
		"non IA5 email":           {0x30, 0x03, 0x81, 0x01, 0xff},
		"non IA5 DNS":             {0x30, 0x03, 0x82, 0x01, 0xff},
		"non IA5 URI":             {0x30, 0x03, 0x86, 0x01, 0xff},
		"empty x400":              {0x30, 0x02, 0xa3, 0x00},
		"invalid directory":       {0x30, 0x05, 0xa4, 0x03, 0x30, 0x01, 0x00},
		"invalid IP length":       {0x30, 0x05, 0x87, 0x03, 1, 2, 3},
		"invalid registered ID":   {0x30, 0x03, 0x88, 0x01, 0x80},
		"otherName missing value": {0x30, 0x05, 0xa0, 0x03, 0x06, 0x01, 0x2a},
		"otherName has two values": {
			0x30, 0x0d, 0xa0, 0x0b, 0x06, 0x01, 0x2a,
			0xa0, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
		},
		"edi missing party": {0x30, 0x09, 0xa5, 0x07, 0xa0, 0x05, 0x0c, 0x03, 'o', 'r', 'g'},
		"edi bad directory string": {
			0x30, 0x05, 0xa5, 0x03, 0xa1, 0x01, 0xff,
		},
		"edi extra data": {
			0x30, 0x0a, 0xa5, 0x08, 0xa1, 0x03, 0x0c, 0x01, 'x', 0x05, 0x00,
		},
	}
	for name, der := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGeneralNames(der); err == nil {
				t.Fatalf("DecodeGeneralNames(%x) accepted malformed DER", der)
			}
		})
	}
	for _, der := range [][]byte{nil, {0x88, 0x00}, {0x88, 0x01, 0x80}} {
		if _, err := DecodeRegisteredID(der); err == nil {
			t.Fatalf("DecodeRegisteredID(%x) accepted malformed DER", der)
		}
	}
}

func TestDecodeNameConstraintsPresenceAndMalformedDER(t *testing.T) {
	minimum, maximum := 1, 0
	permitted := []boundaryConstraintSubtree{
		{name: boundaryGeneralName{tag: 2, content: []byte("example.test")}, minimum: &minimum, maximum: &maximum},
		{name: boundaryGeneralName{tag: 7, content: []byte{192, 0, 2, 0, 255, 255, 255, 0}}},
	}
	excluded := []boundaryConstraintSubtree{
		{name: boundaryGeneralName{tag: 6, content: []byte(".excluded.example")}},
	}
	der := buildBoundaryNameConstraints(permitted, excluded)
	facts, err := DecodeNameConstraintsStrict(der)
	if err != nil {
		t.Fatalf("DecodeNameConstraintsStrict() error = %v", err)
	}
	if len(facts.PermittedSubtrees) != 2 || len(facts.ExcludedSubtrees) != 1 {
		t.Fatalf("name constraints = %#v", facts)
	}
	first := facts.PermittedSubtrees[0]
	if !first.MinimumPresent || first.Minimum != 1 || !first.MaximumPresent || first.Maximum != 0 {
		t.Fatalf("constraint distance presence = %#v", first)
	}
	if facts.PermittedSubtrees[1].MinimumPresent || facts.PermittedSubtrees[1].MaximumPresent {
		t.Fatalf("absent constraint distances became present: %#v", facts.PermittedSubtrees[1])
	}
	for tag := 0; tag <= 8; tag++ {
		want := tag == 1 || tag == 2 || tag == 4 || tag == 6 || tag == 7
		if got := NameConstraintSupportedNameForm(tag); got != want {
			t.Errorf("NameConstraintSupportedNameForm(%d) = %v, want %v", tag, got, want)
		}
	}
	unsupportedDER := buildBoundaryNameConstraints([]boundaryConstraintSubtree{{
		name: boundaryGeneralName{tag: 8, content: []byte{0x2a, 0x03}},
	}}, nil)
	if _, err := DecodeNameConstraints(unsupportedDER); err != nil {
		t.Fatalf("registeredID constraint does not decode: %v", err)
	}

	zero := 0
	validName := boundaryGeneralName{tag: 2, content: []byte("example.test")}
	malformed := map[string][]byte{
		"absent value":         nil,
		"empty sequence":       {0x30, 0x00},
		"empty permitted":      {0x30, 0x02, 0xa0, 0x00},
		"empty subtree":        {0x30, 0x04, 0xa0, 0x02, 0x30, 0x00},
		"explicit default min": buildBoundaryNameConstraints([]boundaryConstraintSubtree{{name: validName, minimum: &zero}}, nil),
		"ordinary IP address": buildBoundaryNameConstraints([]boundaryConstraintSubtree{{
			name: boundaryGeneralName{tag: 7, content: []byte{192, 0, 2, 1}},
		}}, nil),
		"noncontiguous IP mask": buildBoundaryNameConstraints([]boundaryConstraintSubtree{{
			name: boundaryGeneralName{tag: 7, content: []byte{192, 0, 2, 0, 255, 0, 255, 0}},
		}}, nil),
		"duplicate permitted": buildBoundaryNameConstraintFields([]boundaryConstraintField{
			{tag: 0, subtrees: []boundaryConstraintSubtree{{name: validName}}},
			{tag: 0, subtrees: []boundaryConstraintSubtree{{name: validName}}},
		}),
		"out of order": buildBoundaryNameConstraintFields([]boundaryConstraintField{
			{tag: 1, subtrees: []boundaryConstraintSubtree{{name: validName}}},
			{tag: 0, subtrees: []boundaryConstraintSubtree{{name: validName}}},
		}),
		"trailing DER": append(bytes.Clone(der), 0),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNameConstraintsStrict(input); err == nil {
				t.Fatalf("DecodeNameConstraintsStrict(%x) accepted malformed DER", input)
			}
		})
	}
}

func buildBoundaryGeneralNames(names []boundaryGeneralName) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, name := range names {
			addBoundaryGeneralName(sequence, name)
		}
	})
	return builder.BytesOrPanic()
}

func addBoundaryGeneralName(builder *cryptobyte.Builder, name boundaryGeneralName) {
	tag := cryptobyte_asn1.Tag(name.tag).ContextSpecific()
	if name.constructed {
		tag = tag.Constructed()
	}
	builder.AddASN1(tag, func(value *cryptobyte.Builder) { value.AddBytes(name.content) })
}

func boundaryOtherNameContent() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 3, 4})
	builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(value *cryptobyte.Builder) {
		value.AddASN1Int64(7)
	})
	return builder.BytesOrPanic()
}

func boundaryX400Content() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		sequence.AddASN1(cryptobyte_asn1.Tag(3).ContextSpecific(), func(value *cryptobyte.Builder) {
			value.AddBytes([]byte("Org"))
		})
	})
	return builder.BytesOrPanic()
}

func boundaryDirectoryNameDER(commonName string) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(name *cryptobyte.Builder) {
		name.AddASN1(cryptobyte_asn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cryptobyte_asn1.SEQUENCE, func(attribute *cryptobyte.Builder) {
				attribute.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 5, 4, 3})
				attribute.AddASN1(cryptobyte_asn1.UTF8String, func(value *cryptobyte.Builder) {
					value.AddBytes([]byte(commonName))
				})
			})
		})
	})
	return builder.BytesOrPanic()
}

func boundaryEDIPartyContent() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(assigner *cryptobyte.Builder) {
		assigner.AddASN1(cryptobyte_asn1.UTF8String, func(value *cryptobyte.Builder) {
			value.AddBytes([]byte("Earth"))
		})
	})
	builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(party *cryptobyte.Builder) {
		party.AddASN1(cryptobyte_asn1.PrintableString, func(value *cryptobyte.Builder) {
			value.AddBytes([]byte("Party"))
		})
	})
	return builder.BytesOrPanic()
}

type boundaryConstraintSubtree struct {
	name             boundaryGeneralName
	minimum, maximum *int
}

type boundaryConstraintField struct {
	tag      int
	subtrees []boundaryConstraintSubtree
}

func buildBoundaryNameConstraints(permitted, excluded []boundaryConstraintSubtree) []byte {
	var fields []boundaryConstraintField
	if permitted != nil {
		fields = append(fields, boundaryConstraintField{tag: 0, subtrees: permitted})
	}
	if excluded != nil {
		fields = append(fields, boundaryConstraintField{tag: 1, subtrees: excluded})
	}
	return buildBoundaryNameConstraintFields(fields)
}

func buildBoundaryNameConstraintFields(fields []boundaryConstraintField) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, field := range fields {
			sequence.AddASN1(cryptobyte_asn1.Tag(field.tag).ContextSpecific().Constructed(), func(subtrees *cryptobyte.Builder) {
				for _, subtree := range field.subtrees {
					subtrees.AddASN1(cryptobyte_asn1.SEQUENCE, func(encoded *cryptobyte.Builder) {
						addBoundaryGeneralName(encoded, subtree.name)
						addBoundaryDistance(encoded, 0, subtree.minimum)
						addBoundaryDistance(encoded, 1, subtree.maximum)
					})
				}
			})
		}
	})
	return builder.BytesOrPanic()
}

func addBoundaryDistance(builder *cryptobyte.Builder, tag int, distance *int) {
	if distance == nil {
		return
	}
	builder.AddASN1(cryptobyte_asn1.Tag(tag).ContextSpecific(), func(value *cryptobyte.Builder) {
		value.AddBytes([]byte{byte(*distance)})
	})
}
