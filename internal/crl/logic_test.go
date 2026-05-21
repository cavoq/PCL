package crl

import (
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

// TestCertSignsCRL_issuerMatchDoesNotVerifySignature documents that CertSignsCRL
// is a cheap identity hint only. Operators that need cryptographic proof must
// call CheckSignatureFrom (see CRLSignedBy).
func TestCertSignsCRL_issuerMatchDoesNotVerifySignature(t *testing.T) {
	revocationList, err := ParseCRL(mustReadCRLFixture(t))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fakeSigner, err := cryptox509.CreateCertificate(rand.Reader, &cryptox509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      cryptopkix.Name{CommonName: revocationList.Issuer.CommonName},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		SubjectKeyId: revocationList.AuthorityKeyId,
	}, &cryptox509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      cryptopkix.Name{CommonName: "self"},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatalf("create fake signer: %v", err)
	}
	parsed, err := x509.ParseCertificate(fakeSigner)
	if err != nil {
		t.Fatalf("parse fake signer: %v", err)
	}

	if !CertSignsCRL(parsed, revocationList) {
		t.Fatal("CertSignsCRL reports true on DN/AKI match without checking signature")
	}
	if revocationList.CheckSignatureFrom(parsed) == nil {
		t.Fatal("bogus cert must not verify CRL signature")
	}
}

// TestSigningCertFromPool_prefersSignatureOverSubjectSpoof ensures pool order
// cannot pick a non-signing cert that only matches the CRL issuer DN.
func TestSigningCertFromPool_prefersSignatureOverSubjectSpoof(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	caTemplate := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cryptopkix.Name{CommonName: "Real CRL CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02},
	}
	caDER, err := cryptox509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	cryptoCA, err := cryptox509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse crypto CA: %v", err)
	}

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	crlDER, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
		Number:     big.NewInt(1),
	}, cryptoCA, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	revocationList, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}

	spoof := &x509.Certificate{
		Subject:      revocationList.Issuer,
		SubjectKeyId: revocationList.AuthorityKeyId,
		IsCA:         false,
		SerialNumber: big.NewInt(2),
	}

	got := SigningCertFromPool(revocationList, []*x509.Certificate{spoof, ca})
	if got == nil {
		t.Fatal("expected a signer from pool")
	}
	if got == spoof {
		t.Fatal("SigningCertFromPool chose DN-only spoof instead of signature-verified CA")
	}
	if got.Subject.CommonName != "Real CRL CA" {
		t.Fatalf("SigningCertFromPool() CN = %q, want Real CRL CA", got.Subject.CommonName)
	}
}

// TestIsCACRL_BRBoundaryExactlyTenDays is the BR 7.2 subscriber CRL window edge:
// nextUpdate - thisUpdate must be *greater than* 10 days to classify as other CRL.
func TestIsCACRL_BRBoundaryExactlyTenDays(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exactlyTen := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown"},
		ThisUpdate: now,
		NextUpdate: now.Add(subscriberCRLMaxInterval),
	}
	if isCACRL(exactlyTen, nil) {
		t.Fatal("exactly 10-day CRL should be treated as subscriber CRL (isCACRL false)")
	}

	overTen := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown"},
		ThisUpdate: now,
		NextUpdate: now.Add(subscriberCRLMaxInterval + time.Second),
	}
	if !isCACRL(overTen, nil) {
		t.Fatal("CRL validity just over 10 days should infer other CRL profile (isCACRL true)")
	}
}

// TestIsCACRL_longValidityWithNonCASigner uses the same shape as mis-issued CDP
// CRLs: AKI/DN match on a non-CA in the pool must not force subscriber profile
// when validity exceeds 10 days (see TestLetsEncrypt_ISRGRootX1_* for real CRLs).
func TestIsCACRL_longValidityWithNonCASigner(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ee := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Subscriber"},
		SubjectKeyId: []byte{0xaa},
		IsCA:         false,
		SerialNumber: big.NewInt(1),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "Subscriber"},
		AuthorityKeyId: []byte{0xaa},
		ThisUpdate:     now,
		NextUpdate:     now.Add(100 * 24 * time.Hour),
	}

	if !isCACRL(revocationList, []*x509.Certificate{ee}) {
		t.Fatal("long-validity CRL should be isCACRL true even when only matched signer is non-CA")
	}
}
