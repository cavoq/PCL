package aia

import (
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
)

// testSignedLeafPair returns a signed leaf (zcrypto), its real issuer, and a
// decoy with the same subject DN as the issuer but a different key.
func testSignedLeafPair(t *testing.T) (leaf, parent, decoy *zx509.Certificate) {
	t.Helper()

	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate parent key: %v", err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	parentTemplate := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuing CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x0a, 0x0b},
	}
	parentDER, err := stdx509.CreateCertificate(rand.Reader, parentTemplate, parentTemplate, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parent, err = zx509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatalf("parse parent: %v", err)
	}

	decoyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate decoy key: %v", err)
	}
	decoyDER, err := stdx509.CreateCertificate(rand.Reader, parentTemplate, parentTemplate, &decoyKey.PublicKey, decoyKey)
	if err != nil {
		t.Fatalf("create decoy: %v", err)
	}
	decoy, err = zx509.ParseCertificate(decoyDER)
	if err != nil {
		t.Fatalf("parse decoy: %v", err)
	}

	leafTemplate := &stdx509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		Issuer:       parentTemplate.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	leafDER, err := stdx509.CreateCertificate(rand.Reader, leafTemplate, parentTemplate, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err = zx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf, parent, decoy
}

func TestSelectIssuer_signatureBeforeBundleOrder(t *testing.T) {
	leaf, parent, decoy := testSignedLeafPair(t)

	got, matched := SelectIssuer(leaf, []*zx509.Certificate{decoy, parent})
	if !matched || got != parent {
		t.Fatalf("SelectIssuer() = (%v, %v), want (%v, true)", got, matched, parent)
	}
}

func TestSelectIssuer_subjectDNWhenNoRawSignature(t *testing.T) {
	leaf, parent, _ := testSignedLeafPair(t)
	leafNoRaw := &zx509.Certificate{
		Issuer: leaf.Issuer,
	}
	got, matched := SelectIssuer(leafNoRaw, []*zx509.Certificate{parent})
	if !matched || got != parent {
		t.Fatalf("SelectIssuer() = (%v, %v), want (%v, true) via DN hint", got, matched, parent)
	}
}

func TestSelectIssuer_noFallbackWhenOnlyUnrelated(t *testing.T) {
	leaf, _, _ := testSignedLeafPair(t)
	unrelated := &zx509.Certificate{
		Subject:      zpkix.Name{CommonName: "Other CA"},
		SerialNumber: big.NewInt(3),
		IsCA:         true,
	}

	got, matched := SelectIssuer(leaf, []*zx509.Certificate{unrelated})
	if got != nil || matched {
		t.Fatalf("SelectIssuer() = (%v, %v), want (nil, false)", got, matched)
	}
}
