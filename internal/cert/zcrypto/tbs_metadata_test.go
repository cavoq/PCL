package zcrypto

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseTBSCertificateMetadata(t *testing.T) {
	tests := []struct {
		name               string
		serialNumber       []byte
		issuerUniqueID     []byte
		subjectUniqueID    []byte
		wantIssuerPresent  bool
		wantSubjectPresent bool
		wantSubjectBits    int
	}{
		{name: "identifiers absent"},
		{
			name:              "issuer identifier",
			issuerUniqueID:    []byte{0, 0x80},
			wantIssuerPresent: true,
		},
		{
			name:               "subject identifier",
			subjectUniqueID:    []byte{3, 0xa0},
			wantSubjectPresent: true,
			wantSubjectBits:    5,
		},
		{
			name:               "both identifiers",
			issuerUniqueID:     []byte{0, 0x80},
			subjectUniqueID:    []byte{3, 0xa0},
			wantIssuerPresent:  true,
			wantSubjectPresent: true,
			wantSubjectBits:    5,
		},
		{
			name:              "present zero-bit issuer identifier",
			issuerUniqueID:    []byte{0},
			wantIssuerPresent: true,
		},
		{
			name:               "present zero-bit subject identifier",
			subjectUniqueID:    []byte{0},
			wantSubjectPresent: true,
		},
		{
			name:         "serial sign octet preserved",
			serialNumber: []byte{0, 0x80},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawTBS := buildTestTBSCertificate(testTBSOptions{
				serialNumber:    test.serialNumber,
				issuerUniqueID:  test.issuerUniqueID,
				subjectUniqueID: test.subjectUniqueID,
			})
			got, err := parseTBSCertificateMetadata(rawTBS)
			if err != nil {
				t.Fatalf("parse TBSCertificate metadata: %v", err)
			}

			if got.Validity.NotBefore.Tag != 23 ||
				got.Validity.NotBefore.RawValue != "491231235959Z" ||
				got.Validity.NotAfter.Tag != 24 ||
				got.Validity.NotAfter.RawValue != "20500101000000Z" {
				t.Fatalf("unexpected validity metadata: %+v", got.Validity)
			}
			wantSerial := test.serialNumber
			if wantSerial == nil {
				wantSerial = []byte{1}
			}
			if !bytes.Equal(got.SerialNumber.Value, wantSerial) || len(got.SerialNumber.RawDER) == 0 {
				t.Fatalf("unexpected serial metadata: %+v", got.SerialNumber)
			}
			if (got.IssuerUniqueID != nil) != test.wantIssuerPresent {
				t.Fatalf("issuerUniqueID presence = %t, want %t", got.IssuerUniqueID != nil, test.wantIssuerPresent)
			}
			if got.IssuerUniqueID != nil {
				wantBits := (len(test.issuerUniqueID) - 1) * 8
				if got.IssuerUniqueID.BitLength != wantBits ||
					got.IssuerUniqueID.UnusedBits != int(test.issuerUniqueID[0]) ||
					!bytes.Equal(got.IssuerUniqueID.Value, test.issuerUniqueID[1:]) ||
					len(got.IssuerUniqueID.RawDER) == 0 || got.IssuerUniqueID.RawDER[0] != 0x81 {
					t.Fatalf("unexpected issuerUniqueID metadata: %+v", got.IssuerUniqueID)
				}
			}
			if (got.SubjectUniqueID != nil) != test.wantSubjectPresent {
				t.Fatalf(
					"subjectUniqueID presence = %t, want %t",
					got.SubjectUniqueID != nil,
					test.wantSubjectPresent,
				)
			}
			if got.SubjectUniqueID != nil && (got.SubjectUniqueID.BitLength != test.wantSubjectBits ||
				got.SubjectUniqueID.UnusedBits != int(test.subjectUniqueID[0]) ||
				!bytes.Equal(got.SubjectUniqueID.Value, test.subjectUniqueID[1:]) ||
				len(got.SubjectUniqueID.RawDER) == 0 || got.SubjectUniqueID.RawDER[0] != 0x82) {
				t.Fatalf("unexpected subjectUniqueID metadata: %+v", got.SubjectUniqueID)
			}
		})
	}
}

func TestParseTBSCertificateMetadataRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name    string
		options testTBSOptions
		der     []byte
	}{
		{name: "missing TBSCertificate"},
		{
			name: "unsupported time tag",
			options: testTBSOptions{addValidity: func(validity *cryptobyte.Builder) {
				validity.AddASN1(cryptobyte_asn1.IA5String, func(value *cryptobyte.Builder) {
					value.AddBytes([]byte("20491231235959Z"))
				})
				validity.AddASN1GeneralizedTime(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC))
			}},
		},
		{name: "invalid unused-bit count", options: testTBSOptions{issuerUniqueID: []byte{8, 0}}},
		{name: "unused bits without payload", options: testTBSOptions{issuerUniqueID: []byte{1}}},
		{name: "non-zero unused bits", options: testTBSOptions{subjectUniqueID: []byte{3, 0x07}}},
		{
			name: "identifiers out of order",
			options: testTBSOptions{addOptionalFields: func(tbs *cryptobyte.Builder) {
				addTestUniqueIdentifier(tbs, 2, []byte{0, 0x80})
				addTestUniqueIdentifier(tbs, 1, []byte{0, 0x80})
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der := test.der
			if der == nil && test.name != "missing TBSCertificate" {
				der = buildTestTBSCertificate(test.options)
			}
			if _, err := parseTBSCertificateMetadata(der); err == nil {
				t.Fatal("expected malformed metadata to be rejected")
			}
		})
	}
}

func TestParseTBSCertificateMetadataOwnsUniqueIdentifierBytes(t *testing.T) {
	rawTBS := buildTestTBSCertificate(testTBSOptions{issuerUniqueID: []byte{3, 0xa0}})
	got, err := parseTBSCertificateMetadata(rawTBS)
	if err != nil {
		t.Fatalf("parse TBSCertificate metadata: %v", err)
	}
	wantRaw := append([]byte(nil), got.IssuerUniqueID.RawDER...)
	wantValue := append([]byte(nil), got.IssuerUniqueID.Value...)

	for i := range rawTBS {
		rawTBS[i] = 0
	}
	if !bytes.Equal(got.IssuerUniqueID.RawDER, wantRaw) ||
		!bytes.Equal(got.IssuerUniqueID.Value, wantValue) {
		t.Fatal("unique identifier metadata aliases the TBSCertificate input")
	}
}

type testTBSOptions struct {
	addValidity       func(*cryptobyte.Builder)
	serialNumber      []byte
	issuerUniqueID    []byte
	subjectUniqueID   []byte
	addOptionalFields func(*cryptobyte.Builder)
}

func buildTestTBSCertificate(options testTBSOptions) []byte {
	addValidity := options.addValidity
	if addValidity == nil {
		addValidity = func(validity *cryptobyte.Builder) {
			validity.AddASN1UTCTime(time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC))
			validity.AddASN1GeneralizedTime(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC))
		}
	}

	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(version *cryptobyte.Builder) {
			version.AddASN1Int64(2)
		})
		serialNumber := options.serialNumber
		if serialNumber == nil {
			serialNumber = []byte{1}
		}
		tbs.AddASN1(cryptobyte_asn1.INTEGER, func(serial *cryptobyte.Builder) {
			serial.AddBytes(serialNumber)
		})
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, addValidity)
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})
		tbs.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})

		if options.addOptionalFields != nil {
			options.addOptionalFields(tbs)
			return
		}
		if options.issuerUniqueID != nil {
			addTestUniqueIdentifier(tbs, 1, options.issuerUniqueID)
		}
		if options.subjectUniqueID != nil {
			addTestUniqueIdentifier(tbs, 2, options.subjectUniqueID)
		}
	})
	return builder.BytesOrPanic()
}

func addTestUniqueIdentifier(builder *cryptobyte.Builder, tag int, encoded []byte) {
	builder.AddASN1(cryptobyte_asn1.Tag(tag).ContextSpecific(), func(value *cryptobyte.Builder) {
		value.AddBytes(encoded)
	})
}
