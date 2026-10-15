package x509ext

import (
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestDecodeRevocationListStrictIDP(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{name: "indirect", value: []byte{0x30, 0x03, 0x84, 0x01, 0xff}},
		{name: "explicit DEFAULT false", value: []byte{0x30, 0x03, 0x84, 0x01, 0x00}, wantErr: true},
		{name: "empty", value: []byte{0x30, 0x00}, wantErr: true},
		{
			name:    "multiple scope booleans",
			value:   []byte{0x30, 0x06, 0x81, 0x01, 0xff, 0x82, 0x01, 0xff},
			wantErr: true,
		},
		{
			name:    "duplicate field",
			value:   []byte{0x30, 0x06, 0x84, 0x01, 0xff, 0x84, 0x01, 0xff},
			wantErr: true,
		},
		{
			name:    "out of order",
			value:   []byte{0x30, 0x06, 0x84, 0x01, 0xff, 0x81, 0x01, 0xff},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			list := &x509.RevocationList{Extensions: []pkix.Extension{{
				Id:       oidObject(oid.IssuingDistributionPoint),
				Critical: true,
				Value:    test.value,
			}}}
			facts, err := DecodeRevocationListStrict(list)
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeRevocationListStrict() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && !facts.IssuingDistributionPoint.IndirectCRL {
				t.Fatal("indirectCRL was not decoded")
			}
		})
	}
}

func TestDecodeRevocationListStrictAKIPairAndDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{name: "key identifier", value: []byte{0x30, 0x03, 0x80, 0x01, 0xaa}},
		{
			name:  "issuer and serial",
			value: []byte{0x30, 0x08, 0xa1, 0x03, 0x82, 0x01, 'a', 0x82, 0x01, 0x01},
		},
		{name: "issuer without serial", value: []byte{0x30, 0x05, 0xa1, 0x03, 0x82, 0x01, 'a'}, wantErr: true},
		{name: "serial without issuer", value: []byte{0x30, 0x03, 0x82, 0x01, 0x01}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeRevocationListStrict(&x509.RevocationList{Extensions: []pkix.Extension{{
				Id:    oidObject(oid.AuthorityKeyIdentifier),
				Value: test.value,
			}}})
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeRevocationListStrict() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}

	duplicate := pkix.Extension{Id: oidObject(oid.CRLNumber), Value: []byte{0x02, 0x01, 0x01}}
	if _, err := DecodeRevocationListStrict(&x509.RevocationList{
		Extensions: []pkix.Extension{duplicate, duplicate},
	}); err == nil {
		t.Fatal("duplicate CRL extension was accepted")
	}
}

func TestDecodeRevocationListStrictFreshestCRLContext(t *testing.T) {
	valid := []byte{
		0x30, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0xa0, 0x0a,
		0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'a',
	}
	withReasons := []byte{
		0x30, 0x14, 0x30, 0x12, 0xa0, 0x0c, 0xa0, 0x0a,
		0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'a',
		0x81, 0x02, 0x06, 0x40,
	}
	for _, test := range []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{name: "distribution point only", value: valid},
		{name: "reasons forbidden on CRL Freshest", value: withReasons, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts, err := DecodeRevocationListStrict(&x509.RevocationList{Extensions: []pkix.Extension{{
				Id:    oidObject(oid.FreshestCRL),
				Value: test.value,
			}}})
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeRevocationListStrict() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && len(facts.FreshestCRL.Points) != 1 {
				t.Fatalf("Freshest points = %#v", facts.FreshestCRL)
			}
		})
	}
}

func TestDecodeRevocationListStrictEntryExtensions(t *testing.T) {
	validTime := append([]byte{0x18, 0x0f}, []byte("20260814120000Z")...)
	entry := x509.RevokedCertificate{
		Raw:            []byte{0x30, 0x00},
		SerialNumber:   big.NewInt(9),
		RevocationTime: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
		Extensions: []pkix.Extension{
			{Id: oidObject(oid.CRLReason), Value: []byte{0x0a, 0x01, 0x08}},
			{Id: oidObject(oid.InvalidityDate), Value: validTime},
			{
				Id:       oidObject(oid.CertificateIssuer),
				Critical: true,
				Value:    []byte{0x30, 0x03, 0x82, 0x01, 'a'},
			},
		},
	}
	facts, err := DecodeRevocationListStrict(&x509.RevocationList{
		RevokedCertificates: []x509.RevokedCertificate{entry},
	})
	if err != nil {
		t.Fatalf("DecodeRevocationListStrict(): %v", err)
	}
	got := facts.Entries[0]
	if got.ReasonCode.Value != CRLReasonRemoveFromCRL || got.InvalidityDate == nil ||
		got.CertificateIssuer == nil {
		t.Fatalf("entry facts = %#v", got)
	}
	if len(got.UnsupportedCriticalExtensionOIDs) != 0 {
		t.Fatalf("processed certificateIssuer reported unsupported: %#v", got.UnsupportedCriticalExtensionOIDs)
	}
	entry.Raw[0] = 0xff
	validTime[2] = 'X'
	if got.RawDER[0] != 0x30 || got.InvalidityDate.Encoding.RawDER[2] != '2' {
		t.Fatal("decoded entry facts alias caller-owned bytes")
	}

	for _, malformed := range []pkix.Extension{
		{Id: oidObject(oid.CRLReason), Value: []byte{0x0a, 0x01, 0x07}},
		{Id: oidObject(oid.InvalidityDate), Value: append([]byte{0x18, 0x11}, []byte("20260814120000.1Z")...)},
		{Id: oidObject(oid.CertificateIssuer), Critical: true, Value: []byte{0x30, 0x00}},
	} {
		if _, err := DecodeRevocationListStrict(&x509.RevocationList{
			RevokedCertificates: []x509.RevokedCertificate{{Extensions: []pkix.Extension{malformed}}},
		}); err == nil {
			t.Fatalf("malformed entry extension accepted: %s", malformed.Id.String())
		}
	}

	duplicate := pkix.Extension{Id: oidObject(oid.CRLReason), Value: []byte{0x0a, 0x01, 0x01}}
	if _, err := DecodeRevocationListStrict(&x509.RevocationList{
		RevokedCertificates: []x509.RevokedCertificate{{
			Extensions: []pkix.Extension{duplicate, duplicate},
		}},
	}); err == nil {
		t.Fatal("duplicate CRL-entry extension was accepted")
	}
}

func TestDecodeRevocationListStrictReportsUnsupportedCriticalAtBothLocations(t *testing.T) {
	unknown := oidObject("1.2.3.4")
	facts, err := DecodeRevocationListStrict(&x509.RevocationList{
		Extensions: []pkix.Extension{{Id: unknown, Critical: true, Value: []byte{0x05, 0x00}}},
		RevokedCertificates: []x509.RevokedCertificate{{
			Extensions: []pkix.Extension{{Id: unknown, Critical: true, Value: []byte{0x05, 0x00}}},
		}},
	})
	if err != nil {
		t.Fatalf("DecodeRevocationListStrict(): %v", err)
	}
	if len(facts.UnsupportedCriticalExtensionOIDs) != 1 ||
		len(facts.Entries[0].UnsupportedCriticalExtensionOIDs) != 1 {
		t.Fatalf("unsupported critical facts = %#v / %#v",
			facts.UnsupportedCriticalExtensionOIDs,
			facts.Entries[0].UnsupportedCriticalExtensionOIDs,
		)
	}
}

func oidObject(identifier string) zasn1.ObjectIdentifier {
	values := map[string]zasn1.ObjectIdentifier{
		oid.AuthorityKeyIdentifier:   {2, 5, 29, 35},
		oid.CRLNumber:                {2, 5, 29, 20},
		oid.CRLReason:                {2, 5, 29, 21},
		oid.InvalidityDate:           {2, 5, 29, 24},
		oid.DeltaCRLIndicator:        {2, 5, 29, 27},
		oid.IssuingDistributionPoint: {2, 5, 29, 28},
		oid.CertificateIssuer:        {2, 5, 29, 29},
		oid.FreshestCRL:              {2, 5, 29, 46},
		"1.2.3.4":                    {1, 2, 3, 4},
	}
	return values[identifier]
}
