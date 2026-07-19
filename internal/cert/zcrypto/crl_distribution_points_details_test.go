package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"reflect"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestCRLDistributionPointRelativeNameUsesCanonicalRDNProjection(t *testing.T) {
	attribute := commonNameAttributeDER("relative")
	der := buildRelativeNameCRLDP(attribute, 0)
	n, err := ParseCRLDPStrict(der)
	if err != nil {
		t.Fatalf("ParseCRLDPStrict() error = %v", err)
	}

	relative := n.Children["distributionPoints"].Children["0"].
		Children["distributionPoint"].Children["nameRelativeToCRLIssuer"]
	if relative == nil {
		t.Fatal("nameRelativeToCRLIssuer was not projected")
	}
	if commonName := relative.Children["commonName"]; commonName == nil || commonName.Value != "relative" {
		t.Fatalf("commonName = %#v, want relative", commonName)
	}
	if relative.Children["rdns"] == nil || relative.Children["rdns"].Children["0"] == nil {
		t.Fatal("canonical RDN structure is missing")
	}
	wantRDN, _, err := encodeRelativeDistinguishedName(attribute)
	if err != nil {
		t.Fatal(err)
	}
	assertExtensionSchemaBytes(t, relative.Children["raw"].Value, wantRDN)
	assertExtensionSchemaBytes(t, relative.Children["rawValue"].Value, attribute)
	encoded := relative.Children["encoded"].Value.([]byte)
	if len(encoded) == 0 || encoded[0] != byte(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) {
		t.Fatalf("encoded relative name = %x", encoded)
	}
}

func TestDecodeCRLDistributionPointsStrictExposesDependencyFacts(t *testing.T) {
	fullName := buildCRLDPFactsValue()
	facts, err := DecodeCRLDistributionPointsStrict(fullName)
	if err != nil {
		t.Fatalf("DecodeCRLDistributionPointsStrict() error = %v", err)
	}
	if len(facts.DistributionPoints) != 1 {
		t.Fatalf("facts = %#v", facts)
	}
	point := facts.DistributionPoints[0]
	if !point.DistributionPointPresent ||
		point.DistributionPointNameKind != CRLDistributionPointNameFullName ||
		!point.ReasonsPresent ||
		!reflect.DeepEqual(point.ReasonBits, []int{1}) ||
		!reflect.DeepEqual(point.FullNameGeneralNameTags, []int{6}) ||
		!reflect.DeepEqual(point.CRLIssuerGeneralNameTags, []int{2, 4}) {
		t.Fatalf("fullName facts = %#v", point)
	}

	relative := buildRelativeNameCRLDP(commonNameAttributeDER("relative"), 2)
	facts, err = DecodeCRLDistributionPointsStrict(relative)
	if err != nil {
		t.Fatalf("relative DecodeCRLDistributionPointsStrict() error = %v", err)
	}
	point = facts.DistributionPoints[0]
	if point.DistributionPointNameKind != CRLDistributionPointNameRelative ||
		point.ReasonsPresent ||
		!reflect.DeepEqual(point.CRLIssuerGeneralNameTags, []int{4, 4}) {
		t.Fatalf("relative-name dependency facts = %#v", point)
	}
}

func TestCRLDistributionPointRelativeNameRejectsMalformedRDN(t *testing.T) {
	tests := map[string][]byte{
		"empty RDN":       buildRelativeNameCRLDP(nil, 0),
		"wrong attribute": buildRelativeNameCRLDP([]byte{0x02, 0x01, 0x00}, 0),
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCRLDPStrict(der); err == nil {
				t.Fatal("ParseCRLDPStrict() error = nil, want error")
			}
			assertExtensionSchemaValue(t, ParseCRLDP(der), "malformed", true)
		})
	}
}

func TestCRLDistributionPointRejectsReasonsWithoutNameOrIssuer(t *testing.T) {
	der := []byte{0x30, 0x06, 0x30, 0x04, 0x81, 0x02, 0x06, 0x40}
	if _, err := ParseCRLDPStrict(der); err == nil {
		t.Fatal("ParseCRLDPStrict() accepted a reasons-only DistributionPoint")
	}
}

func TestCRLDistributionPointRejectsNonCanonicalOrUndefinedReasonBits(t *testing.T) {
	tests := map[string][]byte{
		"trailing zero named bits": buildCRLDPWithEncodedReasons([]byte{0x00, 0x40}),
		"undefined bit nine":       buildCRLDPWithEncodedReasons([]byte{0x06, 0x00, 0x40}),
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCRLDPStrict(der); err == nil {
				t.Fatal("ParseCRLDPStrict() error = nil, want error")
			}
		})
	}
}

func buildRelativeNameCRLDP(attribute []byte, directoryIssuerCount int) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(points *cryptobyte.Builder) {
		points.AddASN1(cryptobyte_asn1.SEQUENCE, func(point *cryptobyte.Builder) {
			point.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(name *cryptobyte.Builder) {
				name.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(relative *cryptobyte.Builder) {
					relative.AddBytes(attribute)
				})
			})
			if directoryIssuerCount > 0 {
				point.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(issuer *cryptobyte.Builder) {
					for index := 0; index < directoryIssuerCount; index++ {
						issuer.AddASN1(cryptobyte_asn1.Tag(4).ContextSpecific().Constructed(), func(name *cryptobyte.Builder) {
							name.AddBytes(directoryNameConstraintContent())
						})
					}
				})
			}
		})
	})
	return builder.BytesOrPanic()
}

func buildCRLDPFactsValue() []byte {
	return buildCRLDPWithEncodedReasons([]byte{0x06, 0x40})
}

func buildCRLDPWithEncodedReasons(encodedReasons []byte) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(points *cryptobyte.Builder) {
		points.AddASN1(cryptobyte_asn1.SEQUENCE, func(point *cryptobyte.Builder) {
			point.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(name *cryptobyte.Builder) {
				name.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(fullName *cryptobyte.Builder) {
					fullName.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(uri *cryptobyte.Builder) {
						uri.AddBytes([]byte("http://crl.example.test/root.crl"))
					})
				})
			})
			point.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(reasons *cryptobyte.Builder) {
				reasons.AddBytes(encodedReasons)
			})
			point.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(issuer *cryptobyte.Builder) {
				issuer.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(dns *cryptobyte.Builder) {
					dns.AddBytes([]byte("issuer.example.test"))
				})
				issuer.AddASN1(cryptobyte_asn1.Tag(4).ContextSpecific().Constructed(), func(name *cryptobyte.Builder) {
					name.AddBytes(directoryNameConstraintContent())
				})
			})
		})
	})
	return builder.BytesOrPanic()
}

func commonNameAttributeDER(value string) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(attribute *cryptobyte.Builder) {
		attribute.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 5, 4, 3})
		attribute.AddASN1(cryptobyte_asn1.UTF8String, func(encoded *cryptobyte.Builder) {
			encoded.AddBytes([]byte(value))
		})
	})
	return builder.BytesOrPanic()
}

func TestCRLDistributionPointRelativeNameOwnsRawBytes(t *testing.T) {
	der := buildRelativeNameCRLDP(commonNameAttributeDER("owned"), 0)
	n, err := ParseCRLDPStrict(der)
	if err != nil {
		t.Fatal(err)
	}
	relative := n.Children["distributionPoints"].Children["0"].Children["distributionPoint"].Children["nameRelativeToCRLIssuer"]
	want := append([]byte(nil), relative.Children["encoded"].Value.([]byte)...)
	for index := range der {
		der[index] = 0
	}
	if !bytes.Equal(relative.Children["encoded"].Value.([]byte), want) {
		t.Fatal("relative-name encoded DER aliases input")
	}
}
