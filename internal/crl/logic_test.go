package crl

import (
	cryptox509 "crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/testpki"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestCertSignsCRL_nilInputs(t *testing.T) {
	if CertSignsCRL(nil, &x509.RevocationList{}) {
		t.Fatal("nil cert must not sign CRL")
	}
	if CertSignsCRL(&x509.Certificate{}, nil) {
		t.Fatal("nil CRL must not match")
	}
}

func TestSigningCertFromPool_nilCRL(t *testing.T) {
	ca := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if SigningCertFromPool(nil, []*x509.Certificate{ca}) != nil {
		t.Fatal("nil CRL must return nil signer")
	}
}

func TestCertSignsCRLRejectsIssuerMatchWithoutSignature(t *testing.T) {
	revocationList, err := ParseCRL(mustReadCRLFixture(t))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	parsed := testpki.Issue(t, revocationList.Issuer.CommonName, nil, testpki.Serial(99),
		testpki.SubjectKeyID(revocationList.AuthorityKeyId)).Cert

	if CertSignsCRL(parsed, revocationList) {
		t.Fatal("CertSignsCRL must reject DN/AKI match without a valid signature")
	}
	if revocationList.CheckSignatureFrom(parsed) == nil {
		t.Fatal("bogus cert must not verify CRL signature")
	}
}

// TestSigningCertFromPool_prefersSignatureOverSubjectSpoof ensures pool order
// cannot pick a non-signing cert that only matches the CRL issuer DN.
func TestSigningCertFromPool_prefersSignatureOverSubjectSpoof(t *testing.T) {
	issuer := testpki.Issue(t, "Real CRL CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x01, 0x02}))
	ca := issuer.Cert
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	revocationList := parseTestCRL(t, issuer.RevocationList(t, &cryptox509.RevocationList{
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
	}))

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

func TestVerifyingCertFromPoolRejectsSameKeyDifferentSubject(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	options := []testpki.Option{testpki.CA(), testpki.SubjectKeyID([]byte{0xaa}),
		testpki.Validity(now.Add(-time.Hour), now.Add(24*time.Hour))}
	issuer := testpki.Issue(t, "Named CRL Issuer", nil, options...)
	revocationList := parseTestCRL(t, issuer.RevocationList(t, &cryptox509.RevocationList{
		ThisUpdate: now,
		NextUpdate: now.Add(time.Hour),
	}))
	different := testpki.IssueWithKey(t, "Different Subject", issuer.Key, nil,
		append(options, testpki.Serial(2))...).Cert
	if revocationList.CheckSignatureFrom(different) != nil {
		t.Fatal("test setup requires zcrypto signature verification to accept the shared key")
	}
	if got := VerifyingCertFromPool(revocationList, []*x509.Certificate{different}); got != nil {
		t.Fatal("same public key with a different subject must not identify the CRL issuer")
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
