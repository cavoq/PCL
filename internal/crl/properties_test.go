package crl

import (
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestIsIndirectUsesIssuingDistributionPointOID(t *testing.T) {
	indirectValue := []byte{0x30, 0x03, 0x84, 0x01, 0xff}
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{name: "issuing distribution point", oid: asn1.ObjectIdentifier{2, 5, 29, 28}, want: true},
		{name: "certificate issuer is not IDP", oid: asn1.ObjectIdentifier{2, 5, 29, 29}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := &x509.RevocationList{Extensions: []pkix.Extension{{Id: tt.oid, Value: indirectValue}}}
			if got := IsIndirect(list); got != tt.want {
				t.Fatalf("IsIndirect = %v, want %v (IDP OID %s)", got, tt.want, oid.IssuingDistributionPoint)
			}
		})
	}
}

func TestIsIndirectDoesNotScanNestedIDPBytes(t *testing.T) {
	// The byte pattern for indirectCRL TRUE occurs inside an otherName OCTET
	// STRING. A structural decoder must not interpret it as IDP field [4].
	value := []byte{
		0x30, 0x11, 0xa0, 0x0f, 0xa0, 0x0d, 0xa0, 0x0b,
		0x06, 0x02, 0x2a, 0x03, 0xa0, 0x05, 0x04, 0x03, 0x84, 0x01, 0xff,
	}
	list := &x509.RevocationList{Extensions: []pkix.Extension{{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 28},
		Critical: true,
		Value:    value,
	}}}
	if IsIndirect(list) {
		t.Fatal("nested bytes were mistaken for indirectCRL")
	}
}
