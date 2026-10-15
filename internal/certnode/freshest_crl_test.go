package certnode

import (
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestBuildCertificateFreshestCRLUsesSharedStrictDecoder(t *testing.T) {
	valid := []byte{
		0x30, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0xa0, 0x0a,
		0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'a',
	}
	identifier := zasn1.ObjectIdentifier{2, 5, 29, 46}
	tree := BuildTree(&x509.Certificate{Extensions: []pkix.Extension{{
		Id:    identifier,
		Value: valid,
	}}})
	uri, ok := tree.Resolve("extensions.freshestCRL.distributionPoints.0.distributionPoint.fullName.generalNames.0.value")
	if !ok || uri.Value != "http://a" {
		t.Fatalf("Freshest CRL URI projection = %#v (OID %s)", uri, oid.FreshestCRL)
	}

	malformed := BuildTree(&x509.Certificate{Extensions: []pkix.Extension{{
		Id:    identifier,
		Value: []byte{0x30, 0x00},
	}}})
	marker, ok := malformed.Resolve("extensions.freshestCRL.malformed")
	if !ok || marker.Value != true {
		t.Fatalf("Freshest CRL malformed marker = %#v", marker)
	}
}
