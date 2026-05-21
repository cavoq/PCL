package ocsp

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	zx509 "github.com/zmap/zcrypto/x509"
	zx509pkix "github.com/zmap/zcrypto/x509/pkix"
)

func TestSigningIssuerFromPool_prefersSignature(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ocspKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	ca := mustZX509Cert(t, caKey, caKey, &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01},
	}, nil)

	spoof := mustZX509Cert(t, caKey, caKey, &cryptox509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      cryptopkix.Name{CommonName: "CA"},
		SubjectKeyId: []byte{0x01},
	}, nil)

	signer := mustZX509Cert(t, ocspKey, caKey, &cryptox509.Certificate{
		SerialNumber:     big.NewInt(3),
		Subject:          cryptopkix.Name{CommonName: "OCSP"},
		Issuer:           pkixNameToStd(ca.Subject),
		AuthorityKeyId:   ca.SubjectKeyId,
		NotBefore:        ca.NotBefore,
		NotAfter:         ca.NotAfter,
		ExtKeyUsage:      []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageOCSPSigning},
		KeyUsage:         cryptox509.KeyUsageDigitalSignature,
		SubjectKeyId:     []byte{0x02},
	}, toStdCert(ca))

	got := SigningIssuerFromPool(signer, []*zx509.Certificate{spoof, ca})
	if got != ca {
		t.Fatalf("SigningIssuerFromPool() = serial %v, want CA serial %v", got.SerialNumber, ca.SerialNumber)
	}
}

func TestBuildSignerEvalChain_usesTLSChainSuffix(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ocspKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	root := mustZX509Cert(t, caKey, caKey, &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "Root"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x10},
	}, nil)

	intermediate := mustZX509Cert(t, caKey, caKey, &cryptox509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               cryptopkix.Name{CommonName: "Intermediate"},
		Issuer:                pkixNameToStd(root.Subject),
		AuthorityKeyId:        root.SubjectKeyId,
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x11},
	}, toStdCert(root))

	leaf := mustZX509Cert(t, leafKey, caKey, &cryptox509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      cryptopkix.Name{CommonName: "Leaf"},
		Issuer:       pkixNameToStd(intermediate.Subject),
		NotBefore:    root.NotBefore,
		NotAfter:     root.NotAfter,
	}, toStdCert(intermediate))

	ocspSigner := mustZX509Cert(t, ocspKey, caKey, &cryptox509.Certificate{
		SerialNumber:   big.NewInt(4),
		Subject:        cryptopkix.Name{CommonName: "OCSP"},
		Issuer:         pkixNameToStd(intermediate.Subject),
		AuthorityKeyId: intermediate.SubjectKeyId,
		NotBefore:      root.NotBefore,
		NotAfter:       root.NotAfter,
		ExtKeyUsage:    []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageOCSPSigning},
		KeyUsage:       cryptox509.KeyUsageDigitalSignature,
	}, toStdCert(intermediate))

	tlsChain := []*cert.Info{
		{Cert: leaf, FilePath: "leaf.pem"},
		{Cert: intermediate, FilePath: "intermediate.pem"},
		{Cert: root, FilePath: "root.pem"},
	}
	signerInfo := &cert.Info{Cert: ocspSigner, FilePath: "ocsp.pem (signing cert)", Type: "ocspSigning"}

	got := BuildSignerEvalChain(ocspSigner, signerInfo, tlsChain, 0, 0, nil)
	if len(got) != 3 {
		t.Fatalf("BuildSignerEvalChain() len = %d, want 3", len(got))
	}
	if got[0].Cert != ocspSigner {
		t.Fatal("position 0 should be OCSP responder")
	}
	if got[1].Cert != intermediate || got[2].Cert != root {
		t.Fatalf("tail = %q -> %q, want intermediate -> root",
			got[1].Cert.Subject.CommonName, got[2].Cert.Subject.CommonName)
	}
	if got[0].Type != "ocspSigning" {
		t.Fatalf("signer type = %q, want ocspSigning", got[0].Type)
	}
	if got[1].Type != "intermediate" || got[2].Type != "root" {
		t.Fatalf("types = %q, %q", got[1].Type, got[2].Type)
	}
}

func TestBuildSignerEvalChain_resolvesViaAIA(t *testing.T) {
	ocspKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	parentDER, parent, parentKey := testOCSPParentCA(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	signer := mustZX509Cert(t, ocspKey, parentKey, &cryptox509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               cryptopkix.Name{CommonName: "OCSP"},
		Issuer:                pkixNameToStd(parent.Subject),
		AuthorityKeyId:        parent.SubjectKeyId,
		NotBefore:             parent.NotBefore,
		NotAfter:              parent.NotAfter,
		IssuingCertificateURL: []string{server.URL},
		ExtKeyUsage:           []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageOCSPSigning},
		KeyUsage:              cryptox509.KeyUsageDigitalSignature,
	}, toStdCert(parent))

	tlsChain := []*cert.Info{}
	signerInfo := &cert.Info{Cert: signer, FilePath: "ocsp.pem"}

	got := BuildSignerEvalChain(signer, signerInfo, tlsChain, time.Second, 2, nil)
	if len(got) < 2 {
		t.Fatalf("BuildSignerEvalChain() len = %d, want responder + issuer", len(got))
	}
	if got[0].Cert != signer {
		t.Fatal("position 0 should be OCSP responder")
	}
	if got[1].Cert.Subject.CommonName != parent.Subject.CommonName {
		t.Fatalf("issuer CN = %q, want %q", got[1].Cert.Subject.CommonName, parent.Subject.CommonName)
	}
}

func pkixNameToStd(n zx509pkix.Name) cryptopkix.Name {
	return cryptopkix.Name{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
	}
}

func toStdCert(c *zx509.Certificate) *cryptox509.Certificate {
	if c == nil {
		return nil
	}
	std, err := cryptox509.ParseCertificate(c.Raw)
	if err != nil {
		return &cryptox509.Certificate{Raw: c.Raw}
	}
	return std
}

func mustZX509Cert(t *testing.T, pubKey, signKey *rsa.PrivateKey, template, parent *cryptox509.Certificate) *zx509.Certificate {
	t.Helper()
	parentStd := template
	if parent != nil {
		parentStd = parent
	}
	signerKey := signKey
	if parent == nil {
		signerKey = pubKey
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, parentStd, &pubKey.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	c, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c
}

func testOCSPParentCA(t *testing.T) ([]byte, *zx509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "OCSP CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x0a},
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return der, parsed, key
}

func TestSigningIssuerFromPool_nilSigner(t *testing.T) {
	if got := SigningIssuerFromPool(nil, []*zx509.Certificate{{}}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestBuildSignerEvalChain_nilSignerReturnsTLSChain(t *testing.T) {
	tls := []*cert.Info{{Cert: &zx509.Certificate{SerialNumber: big.NewInt(1)}}}
	got := BuildSignerEvalChain(nil, &cert.Info{}, tls, 0, 0, nil)
	if len(got) != len(tls) {
		t.Fatalf("len = %d, want %d", len(got), len(tls))
	}
}

func TestCertMatchesSignerIssuer_akiOnly(t *testing.T) {
	signer := &zx509.Certificate{
		Issuer:         zx509pkix.Name{CommonName: "X"},
		AuthorityKeyId: []byte{0xab},
	}
	candidate := &zx509.Certificate{
		Subject:      zx509pkix.Name{CommonName: "Y"},
		SubjectKeyId: []byte{0xab},
	}
	if !certMatchesSignerIssuer(signer, candidate) {
		t.Fatal("expected AKI match")
	}
	if certMatchesSignerIssuer(signer, &zx509.Certificate{SubjectKeyId: []byte{0x00}}) {
		t.Fatal("expected no match")
	}
}
