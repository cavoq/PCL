package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseKeyUsageStrictPreservesBoundaryBitsAndAliases(t *testing.T) {
	der := []byte{0x03, 0x03, 0x07, 0x80, 0x80}
	n, err := ParseKeyUsageStrict(der)
	if err != nil {
		t.Fatalf("ParseKeyUsageStrict() error = %v", err)
	}

	if n.Value != (1 | 1<<8) {
		t.Fatalf("keyUsage value = %#v, want %d", n.Value, 1|1<<8)
	}
	for path, want := range map[string]any{
		"digitalSignature":  true,
		"decipherOnly":      true,
		"contentCommitment": false,
		"nonRepudiation":    false,
		"bitLength":         9,
		"unusedBits":        7,
	} {
		assertExtensionSchemaValue(t, n, path, want)
	}
	assertExtensionSchemaBytes(t, n.Children["raw"].Value, der)
	assertExtensionSchemaBytes(t, n.Children["rawValue"].Value, []byte{0x80, 0x80})
}

func TestParseKeyUsageStrictAllowsStructurallyEmptyNamedBitList(t *testing.T) {
	n, err := ParseKeyUsageStrict([]byte{0x03, 0x01, 0x00})
	if err != nil {
		t.Fatalf("ParseKeyUsageStrict() error = %v", err)
	}
	if n.Value != 0 {
		t.Fatalf("keyUsage value = %#v, want 0", n.Value)
	}
	assertExtensionSchemaValue(t, n, "bitLength", 0)
	assertExtensionSchemaValue(t, n, "digitalSignature", false)
}

func TestParseKeyUsageRejectsNonCanonicalAndUndefinedBits(t *testing.T) {
	tests := map[string][]byte{
		"trailing zero named bits": {0x03, 0x02, 0x00, 0x80},
		"undefined bit nine":       {0x03, 0x03, 0x06, 0x00, 0x40},
		"nonzero unused bits":      {0x03, 0x02, 0x07, 0x81},
		"trailing DER":             {0x03, 0x02, 0x07, 0x80, 0x00},
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKeyUsageStrict(der); err == nil {
				t.Fatal("ParseKeyUsageStrict() error = nil, want error")
			}
			compat := ParseKeyUsage(der)
			assertExtensionSchemaValue(t, compat, "malformed", true)
			assertExtensionSchemaBytes(t, compat.Children["raw"].Value, der)
		})
	}
}

func TestParseBasicConstraintsStrictPreservesPresence(t *testing.T) {
	tests := []struct {
		name        string
		der         []byte
		ca          bool
		caPresent   bool
		path        int
		pathPresent bool
	}{
		{name: "defaults absent", der: []byte{0x30, 0x00}},
		{
			name:      "CA without path length",
			der:       []byte{0x30, 0x03, 0x01, 0x01, 0xff},
			ca:        true,
			caPresent: true,
		},
		{
			name:        "CA with zero path length",
			der:         []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00},
			ca:          true,
			caPresent:   true,
			pathPresent: true,
		},
		{
			name:        "path dependency retained for domain",
			der:         []byte{0x30, 0x03, 0x02, 0x01, 0x02},
			path:        2,
			pathPresent: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n, err := ParseBasicConstraintsStrict(test.der)
			if err != nil {
				t.Fatalf("ParseBasicConstraintsStrict() error = %v", err)
			}
			assertExtensionSchemaValue(t, n, "cA", test.ca)
			assertExtensionSchemaValue(t, n, "cAPresent", test.caPresent)
			assertExtensionSchemaValue(t, n, "pathLenConstraintPresent", test.pathPresent)
			if test.pathPresent {
				if got := n.Children["pathLenConstraint"].Value; got != test.path {
					t.Fatalf("pathLenConstraint = %#v, want %d", got, test.path)
				}
			} else if n.Children["pathLenConstraint"] != nil {
				t.Fatal("absent pathLenConstraint was projected")
			}
			assertExtensionSchemaBytes(t, n.Children["raw"].Value, test.der)
		})
	}
}

func TestParseBasicConstraintsRejectsMalformedAndExplicitDefault(t *testing.T) {
	tests := map[string][]byte{
		"explicit DEFAULT cA false": {0x30, 0x03, 0x01, 0x01, 0x00},
		"negative path length":      {0x30, 0x03, 0x02, 0x01, 0xff},
		"redundant integer zero":    {0x30, 0x04, 0x02, 0x02, 0x00, 0x00},
		"fields out of order":       {0x30, 0x06, 0x02, 0x01, 0x00, 0x01, 0x01, 0xff},
		"trailing DER":              {0x30, 0x00, 0x00},
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBasicConstraintsStrict(der); err == nil {
				t.Fatal("ParseBasicConstraintsStrict() error = nil, want error")
			}
			assertExtensionSchemaValue(t, ParseBasicConstraints(der), "malformed", true)
		})
	}
}

func TestParseExtKeyUsageStrictPreservesAnyKnownAndUnknownOIDs(t *testing.T) {
	unknownOID := stdasn1.ObjectIdentifier{1, 2, 3, 4}
	der := buildExtendedKeyUsageValue(
		stdasn1.ObjectIdentifier{2, 5, 29, 37, 0},
		stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1},
		unknownOID,
	)
	wireDER := append([]byte(nil), der...)
	n, err := ParseExtKeyUsageStrict(der)
	if err != nil {
		t.Fatalf("ParseExtKeyUsageStrict() error = %v", err)
	}

	assertExtensionSchemaValue(t, n, "count", 3)
	assertExtensionSchemaValue(t, n, "any", true)
	assertExtensionSchemaValue(t, n, "serverAuth", true)
	assertExtensionSchemaValue(t, n.Children["usages"].Children["2"], "oid", unknownOID.String())
	assertExtensionSchemaValue(t, n.Children["unknown"], "count", 1)
	if got := n.Children["unknown"].Children["0"].Value; got != unknownOID.String() {
		t.Fatalf("unknown EKU value = %#v, want %q", got, unknownOID.String())
	}
	assertExtensionSchemaBytes(t, n.Children["raw"].Value, der)

	want := append([]byte(nil), n.Children["usages"].Children["2"].Children["raw"].Value.([]byte)...)
	for index := range der {
		der[index] = 0
	}
	if !bytes.Equal(n.Children["usages"].Children["2"].Children["raw"].Value.([]byte), want) {
		t.Fatal("projected EKU raw DER aliases input")
	}

	identifiers, err := DecodeExtendedKeyUsageOIDsStrict(wireDER)
	if err != nil {
		t.Fatalf("DecodeExtendedKeyUsageOIDsStrict() error = %v", err)
	}
	wantIdentifiers := []string{anyExtendedKeyUsageOID, oid.ServerAuth, unknownOID.String()}
	if !slices.Equal(identifiers, wantIdentifiers) {
		t.Fatalf("DecodeExtendedKeyUsageOIDsStrict() = %q, want %q", identifiers, wantIdentifiers)
	}
}

func TestParseExtKeyUsageRejectsEmptyAndMalformedSequences(t *testing.T) {
	tests := map[string][]byte{
		"empty":          {0x30, 0x00},
		"empty OID":      {0x30, 0x02, 0x06, 0x00},
		"wrong element":  {0x30, 0x03, 0x02, 0x01, 0x01},
		"trailing bytes": append(buildExtendedKeyUsageValue(stdasn1.ObjectIdentifier{1, 2, 3}), 0),
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseExtKeyUsageStrict(der); err == nil {
				t.Fatal("ParseExtKeyUsageStrict() error = nil, want error")
			}
			assertExtensionSchemaValue(t, ParseExtKeyUsage(der), "malformed", true)
		})
	}
}

func buildExtendedKeyUsageValue(identifiers ...stdasn1.ObjectIdentifier) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, identifier := range identifiers {
			sequence.AddASN1ObjectIdentifier(identifier)
		}
	})
	return builder.BytesOrPanic()
}
