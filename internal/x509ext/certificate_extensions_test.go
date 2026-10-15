package x509ext

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestDecodeAuthorityInformationAccessBoundary(t *testing.T) {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(descriptions *cryptobyte.Builder) {
		descriptions.AddASN1(cryptobyte_asn1.SEQUENCE, func(description *cryptobyte.Builder) {
			description.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1})
			description.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(location *cryptobyte.Builder) {
				location.AddBytes([]byte("https://ocsp.example.test"))
			})
		})
	})
	der := builder.BytesOrPanic()
	descriptions, err := DecodeAuthorityInformationAccess(der)
	if err != nil {
		t.Fatalf("DecodeAuthorityInformationAccess() error = %v", err)
	}
	if len(descriptions) != 1 || descriptions[0].Method != oid.AccessMethodOCSP ||
		descriptions[0].Location.Tag != 6 ||
		string(descriptions[0].Location.RawValue) != "https://ocsp.example.test" {
		t.Fatalf("descriptions = %#v", descriptions)
	}

	malformed := map[string][]byte{
		"absent value":        nil,
		"empty sequence":      {0x30, 0x00},
		"wrong outer tag":     {0x31, 0x00},
		"wrong entry tag":     {0x30, 0x03, 0x02, 0x01, 0x00},
		"missing method":      {0x30, 0x04, 0x30, 0x02, 0x86, 0x00},
		"missing location":    {0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04},
		"extra entry data":    {0x30, 0x0c, 0x30, 0x0a, 0x06, 0x02, 0x2a, 0x03, 0x86, 0x01, 'x', 0x05, 0x00},
		"trailing outer data": append(bytes.Clone(der), 0),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAuthorityInformationAccess(input); err == nil {
				t.Fatalf("DecodeAuthorityInformationAccess(%x) accepted malformed DER", input)
			}
		})
	}
}

func TestDecodeKeyExtensionsPreservesPresenceAndUnknownUsages(t *testing.T) {
	usage, err := DecodeKeyUsage([]byte{0x03, 0x03, 0x07, 0x80, 0x80})
	if err != nil {
		t.Fatalf("DecodeKeyUsage() error = %v", err)
	}
	if usage.Value != 1|1<<8 || usage.BitLength != 9 || usage.UnusedBits != 7 {
		t.Fatalf("key usage = %#v", usage)
	}

	emptyUsage, err := DecodeKeyUsage([]byte{0x03, 0x01, 0x00})
	if err != nil || emptyUsage.Value != 0 || emptyUsage.BitLength != 0 {
		t.Fatalf("empty key usage = %#v, %v", emptyUsage, err)
	}

	for name, der := range map[string][]byte{
		"wrong tag":          {0x04, 0x01, 0x00},
		"undefined bit":      {0x03, 0x03, 0x06, 0x00, 0x40},
		"trailing zero bit":  {0x03, 0x02, 0x00, 0x80},
		"nonzero unused bit": {0x03, 0x02, 0x07, 0x81},
		"trailing DER":       {0x03, 0x01, 0x00, 0x00},
	} {
		t.Run("key usage "+name, func(t *testing.T) {
			if _, err := DecodeKeyUsage(der); err == nil {
				t.Fatalf("DecodeKeyUsage(%x) accepted malformed DER", der)
			}
		})
	}

	constraints, err := DecodeBasicConstraintsStrict([]byte{0x30, 0x00})
	if err != nil || constraints.CAPresent || constraints.PathLenConstraintPresent {
		t.Fatalf("absent BasicConstraints values = %#v, %v", constraints, err)
	}
	constraints, err = DecodeBasicConstraintsStrict(
		[]byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00},
	)
	if err != nil || !constraints.CA || !constraints.CAPresent ||
		!constraints.PathLenConstraintPresent || constraints.PathLenConstraint != 0 {
		t.Fatalf("present BasicConstraints values = %#v, %v", constraints, err)
	}
	for name, der := range map[string][]byte{
		"explicit default": {0x30, 0x03, 0x01, 0x01, 0x00},
		"negative path":    {0x30, 0x03, 0x02, 0x01, 0xff},
		"out of order":     {0x30, 0x06, 0x02, 0x01, 0x00, 0x01, 0x01, 0xff},
		"unknown field":    {0x30, 0x02, 0x05, 0x00},
		"trailing DER":     {0x30, 0x00, 0x00},
	} {
		t.Run("basic constraints "+name, func(t *testing.T) {
			if _, err := DecodeBasicConstraintsStrict(der); err == nil {
				t.Fatalf("DecodeBasicConstraintsStrict(%x) accepted malformed DER", der)
			}
		})
	}

	var ekuBuilder cryptobyte.Builder
	ekuBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		sequence.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 5, 29, 37, 0})
		sequence.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		sequence.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 3, 4})
	})
	identifiers, err := DecodeExtendedKeyUsageOIDsStrict(ekuBuilder.BytesOrPanic())
	if err != nil {
		t.Fatalf("DecodeExtendedKeyUsageOIDsStrict() error = %v", err)
	}
	wantIdentifiers := []string{AnyExtendedKeyUsageOID, oid.ServerAuth, "1.2.3.4"}
	if !slices.Equal(identifiers, wantIdentifiers) {
		t.Fatalf("extended key usages = %q, want %q", identifiers, wantIdentifiers)
	}
	for identifier, want := range map[string]string{
		AnyExtendedKeyUsageOID: "any",
		oid.ServerAuth:         "serverAuth",
		oid.ClientAuth:         "clientAuth",
		oid.CodeSigning:        "codeSigning",
		oid.EmailProtection:    "emailProtection",
		oid.TimeStamping:       "timeStamping",
		oid.OCSPSigning:        "ocspSigning",
	} {
		if got, ok := ExtendedKeyUsageName(identifier); !ok || got != want {
			t.Errorf("ExtendedKeyUsageName(%q) = %q, %t; want %q", identifier, got, ok, want)
		}
	}
	if _, ok := ExtendedKeyUsageName("1.2.3.4"); ok {
		t.Fatal("unknown extended key usage received a friendly name")
	}
	for name, der := range map[string][]byte{
		"absent":         nil,
		"empty":          {0x30, 0x00},
		"wrong element":  {0x30, 0x03, 0x02, 0x01, 0x01},
		"malformed OID":  {0x30, 0x02, 0x06, 0x00},
		"trailing bytes": append(ekuBuilder.BytesOrPanic(), 0),
	} {
		t.Run("extended key usage "+name, func(t *testing.T) {
			if _, err := DecodeExtendedKeyUsage(der); err == nil {
				t.Fatalf("DecodeExtendedKeyUsage(%x) accepted malformed DER", der)
			}
		})
	}
}

func TestDecodePolicyExtensionsBoundary(t *testing.T) {
	var mappingsBuilder cryptobyte.Builder
	mappingsBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, pair := range [][2]stdasn1.ObjectIdentifier{
			{{2, 5, 29, 32, 0}, {1, 2, 3, 4}},
			{{1, 2, 3, 5}, {2, 5, 29, 32, 0}},
		} {
			sequence.AddASN1(cryptobyte_asn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
				mapping.AddASN1ObjectIdentifier(pair[0])
				mapping.AddASN1ObjectIdentifier(pair[1])
			})
		}
	})
	mappingsDER := mappingsBuilder.BytesOrPanic()
	mappings, err := DecodePolicyMappingsStrict(mappingsDER)
	if err != nil || len(mappings) != 2 || mappings[0].IssuerDomainPolicy != oid.AnyPolicy ||
		mappings[1].SubjectDomainPolicy != oid.AnyPolicy || len(mappings[0].RawDER) == 0 {
		t.Fatalf("policy mappings = %#v, %v", mappings, err)
	}
	for name, der := range map[string][]byte{
		"absent":        nil,
		"empty":         {0x30, 0x00},
		"wrong entry":   {0x30, 0x03, 0x02, 0x01, 0x00},
		"one OID":       {0x30, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2a, 0x03},
		"three OIDs":    {0x30, 0x0e, 0x30, 0x0c, 0x06, 0x02, 0x2a, 0x03, 0x06, 0x02, 0x2a, 0x04, 0x06, 0x02, 0x2a, 0x05},
		"trailing data": append(bytes.Clone(mappingsDER), 0),
	} {
		t.Run("policy mappings "+name, func(t *testing.T) {
			if _, err := DecodePolicyMappingsStrict(der); err == nil {
				t.Fatalf("DecodePolicyMappingsStrict(%x) accepted malformed DER", der)
			}
		})
	}

	constraintsDER := []byte{0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, 0x00, 0xff}
	constraints, err := DecodePolicyConstraintsStrict(constraintsDER)
	if err != nil || !constraints.RequireExplicitPolicyPresent || constraints.RequireExplicitPolicy != 0 ||
		!constraints.InhibitPolicyMappingPresent || constraints.InhibitPolicyMapping != 255 {
		t.Fatalf("policy constraints = %#v, %v", constraints, err)
	}
	for name, der := range map[string][]byte{
		"absent":                 nil,
		"empty":                  {0x30, 0x00},
		"negative":               {0x30, 0x03, 0x80, 0x01, 0xff},
		"redundant leading zero": {0x30, 0x04, 0x80, 0x02, 0x00, 0x01},
		"out of order":           {0x30, 0x06, 0x81, 0x01, 0x00, 0x80, 0x01, 0x00},
		"duplicate":              {0x30, 0x06, 0x80, 0x01, 0x00, 0x80, 0x01, 0x01},
		"trailing DER":           append(bytes.Clone(constraintsDER), 0),
	} {
		t.Run("policy constraints "+name, func(t *testing.T) {
			if _, err := DecodePolicyConstraintsStrict(der); err == nil {
				t.Fatalf("DecodePolicyConstraintsStrict(%x) accepted malformed DER", der)
			}
		})
	}

	value, err := DecodeInhibitAnyPolicyStrict([]byte{0x02, 0x02, 0x00, 0xff})
	if err != nil || value.Scalar() != 255 {
		t.Fatalf("DecodeInhibitAnyPolicyStrict() = %#v, %v", value, err)
	}
	large, err := DecodeInhibitAnyPolicyStrict(
		[]byte{0x02, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	)
	if err != nil || large.Scalar() != "18446744073709551616" {
		t.Fatalf("large SkipCerts scalar = %#v, %v", large.Scalar(), err)
	}
}
