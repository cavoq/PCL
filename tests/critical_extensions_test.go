package tests

import (
	"io"
	"testing"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/certnode"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/testfiles"
	"github.com/cavoq/PCL/internal/x509ext"
)

// TestCriticalExtensionDecisionsAgree checks that the path domain decision
// and the noUnknownCriticalExtensions operator over the certificate node tree
// accept and reject the same certificates.
func TestCriticalExtensionDecisionsAgree(t *testing.T) {
	var certificates []*x509.Certificate
	for _, dir := range []string{testfiles.PKITSCerts(), testfiles.Certs()} {
		infos, err := cert.LoadCertificates(dir, io.Discard)
		if err != nil {
			t.Fatalf("load %s: %v", dir, err)
		}
		for _, info := range infos {
			certificates = append(certificates, info.Cert)
		}
	}
	for _, crafted := range []struct {
		identifier zasn1.ObjectIdentifier
		value      []byte
	}{
		{zasn1.ObjectIdentifier{2, 5, 29, 15}, []byte{0x04, 0x00}},
		{zasn1.ObjectIdentifier{2, 5, 29, 17}, []byte{0x30, 0x02, 0x82, 0x05}},
		{zasn1.ObjectIdentifier{2, 5, 29, 30}, []byte{0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0x88, 0x02, 0x2a, 0x03}},
		// A dNSName subtree with a leading period is malformed.
		{zasn1.ObjectIdentifier{2, 5, 29, 30}, []byte{0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0x82, 0x02, 0x2e, 0x61}},
		{zasn1.ObjectIdentifier{2, 5, 29, 32}, []byte{
			0x30, 0x10, 0x30, 0x0e, 0x06, 0x02, 0x2a, 0x03,
			0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2a, 0x04, 0x05, 0x00,
		}},
	} {
		for _, critical := range []bool{true, false} {
			certificates = append(certificates, &x509.Certificate{Extensions: []pkix.Extension{{
				Id: crafted.identifier, Critical: critical, Value: crafted.value,
			}}})
		}
	}

	accepted, rejected := 0, 0
	for _, certificate := range certificates {
		domain := x509ext.CertificateCriticalExtensionsProcessable(certificate.Extensions)
		projected, err := operator.NoUnknownCriticalExtensions{}.Evaluate(certnode.BuildTree(certificate), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if domain != projected {
			t.Errorf("%s: domain decision %v, node operator %v", certificate.Subject, domain, projected)
		}
		if domain {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted == 0 || rejected < 5 {
		t.Fatalf("corpus lacks coverage: %d accepted, %d rejected", accepted, rejected)
	}
}
