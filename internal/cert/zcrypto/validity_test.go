package zcrypto

import (
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseValidityEncoding(t *testing.T) {
	notBefore := time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	notAfter := time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	rawTBS := buildTestTBSCertificate(func(validity *cryptobyte.Builder) {
		validity.AddASN1UTCTime(notBefore)
		validity.AddASN1GeneralizedTime(notAfter)
	})

	got, err := parseValidityEncoding(rawTBS)
	if err != nil {
		t.Fatalf("parse validity encoding: %v", err)
	}
	if got.NotBefore.Tag != 23 || !got.NotBefore.IsUTC || got.NotBefore.RawString != "491231235959Z" {
		t.Fatalf("unexpected notBefore encoding: %+v", got.NotBefore)
	}
	if got.NotAfter.Tag != 24 || got.NotAfter.IsUTC || got.NotAfter.RawString != "20500101000000Z" {
		t.Fatalf("unexpected notAfter encoding: %+v", got.NotAfter)
	}
}

func TestParseValidityEncodingRejectsMalformedStructure(t *testing.T) {
	tests := []struct {
		name string
		der  []byte
	}{
		{name: "missing TBSCertificate", der: nil},
		{name: "missing validity", der: []byte{0x30, 0x00}},
		{
			name: "unsupported time tag",
			der: buildTestTBSCertificate(func(validity *cryptobyte.Builder) {
				validity.AddASN1(cryptobyte_asn1.IA5String, func(value *cryptobyte.Builder) {
					value.AddBytes([]byte("20491231235959Z"))
				})
				validity.AddASN1GeneralizedTime(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC))
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseValidityEncoding(tt.der); err == nil {
				t.Fatal("expected malformed validity to be rejected")
			}
		})
	}
}

func buildTestTBSCertificate(addValidity func(*cryptobyte.Builder)) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(version *cryptobyte.Builder) {
			version.AddASN1Int64(2)
		})
		tbs.AddASN1Int64(1)
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, addValidity)
	})
	return builder.BytesOrPanic()
}
