package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
)

func TestClimbChainWithPool_usesPoolWhenNoCaIssuers(t *testing.T) {
	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate parent key: %v", err)
	}
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	parentStd := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Pool Parent CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02},
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, parentStd, parentStd, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parent, err := zx509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatalf("parse parent: %v", err)
	}
	parentInfo := &Info{Cert: parent, FilePath: "/trusted/parent.pem"}

	interStd := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "No AIA Intermediate"},
		Issuer:                parentStd.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x03, 0x04},
		// No IssuingCertificateURL — climb must use pool
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interStd, parentStd, &interKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	intermediate, err := zx509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	interInfo := &Info{Cert: intermediate, FilePath: "intermediate.cer"}

	leafStd := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "sub.example"},
		Issuer:       interStd.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafStd, interStd, &interKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := zx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	leafInfo := &Info{Cert: leaf, FilePath: "leaf.pem"}

	pool := []*Info{parentInfo}
	got := ClimbChainWithPool([]*Info{leafInfo, interInfo}, pool, time.Second, 2, nil)
	if len(got) != 3 {
		t.Fatalf("got %d certs, want leaf + intermediate + pool parent", len(got))
	}
	if got[2].Cert.Subject.CommonName != "Pool Parent CA" {
		t.Fatalf("parent CN = %q", got[2].Cert.Subject.CommonName)
	}
	if got[2].FilePath != "/trusted/parent.pem" {
		t.Fatalf("parent path = %q", got[2].FilePath)
	}
	if leaf.CheckSignatureFrom(intermediate) != nil || intermediate.CheckSignatureFrom(parent) != nil {
		t.Fatal("setup signatures invalid")
	}
}

func TestClimbChainWithPool_doesNotUseDNOnlyPoolMatch(t *testing.T) {
	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	impostorStd := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Wrong Parent"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	impostorDER, err := x509.CreateCertificate(rand.Reader, impostorStd, impostorStd, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create impostor: %v", err)
	}
	impostorZ, err := zx509.ParseCertificate(impostorDER)
	if err != nil {
		t.Fatalf("parse impostor: %v", err)
	}

	childStd := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "child"},
		Issuer:       pkix.Name{CommonName: "Wrong Parent"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	childDER, err := x509.CreateCertificate(rand.Reader, childStd, impostorStd, &parentKey.PublicKey, parentKey)
	_ = impostorZ
	if err != nil {
		t.Fatalf("create child: %v", err)
	}
	child, err := zx509.ParseCertificate(childDER)
	if err != nil {
		t.Fatalf("parse child: %v", err)
	}

	// Pool has unrelated CA that does not sign child
	realParentStd := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Real Parent"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	realKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate real key: %v", err)
	}
	realDER, err := x509.CreateCertificate(rand.Reader, realParentStd, realParentStd, &realKey.PublicKey, realKey)
	if err != nil {
		t.Fatalf("create real parent: %v", err)
	}
	realParent, err := zx509.ParseCertificate(realDER)
	if err != nil {
		t.Fatalf("parse real parent: %v", err)
	}

	child.Issuer = realParent.Subject // DN matches real parent but signed by impostor
	pool := []*Info{{Cert: realParent, FilePath: "real.pem"}}

	got := ClimbChainWithPool([]*Info{{Cert: child, FilePath: "child.pem"}}, pool, time.Second, 1, nil)
	if len(got) != 1 {
		t.Fatalf("got %d certs, want 1 (no DN-only pool link)", len(got))
	}
}

func TestClimbChainWithPool_maxDepthZero(t *testing.T) {
	leaf := &Info{Cert: &zx509.Certificate{SerialNumber: big.NewInt(1)}}
	got := ClimbChainWithPool([]*Info{leaf}, nil, time.Second, 0, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want unchanged chain", len(got))
	}
}

func TestClimbChainWithPool_emitsWarningOnFetchFailure(t *testing.T) {
	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate parent key: %v", err)
	}
	childKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate child key: %v", err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	parentStd := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Parent CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	childStd := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "child"},
		Issuer:                parentStd.Subject,
		IssuingCertificateURL: []string{"http://127.0.0.1:1/unreachable"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, childStd, parentStd, &childKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	childZ, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	got := ClimbChainWithPool([]*Info{{Cert: childZ, FilePath: "child.pem"}}, nil, 50*time.Millisecond, 2, &buf)
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if buf.Len() == 0 {
		t.Fatal("expected warning when CA Issuers fetch fails")
	}
}
