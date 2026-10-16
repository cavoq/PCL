package cert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/aia"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testfiles"
	"github.com/cavoq/PCL/internal/testpki"
	zx509 "github.com/zmap/zcrypto/x509"
)

// LE fixture layout (pinned from letsencrypt.org / x2.i.lencr.org):
//
//	e9.der              — Let's Encrypt E9 intermediate (issuer ISRG Root X2)
//	isrg-root-x2.der    — ISRG Root X2 (real parent; signs E9)
//
// Live CA Issuers at http://x2.i.lencr.org/ currently returns a single DER cert.
// This test serves a PKCS#7 bundle like historical multi-cert AIA responses:
// [DN+AKI impostor first, real signing parent second] so ClimbChain must verify
// signatures, not identity hints alone.
func TestClimbChain_lePKCS7Bundle_selectsSigningParent(t *testing.T) {
	e9, realRoot := leIssuerBundle(t)
	chain := []*Info{{Cert: e9, FilePath: "e9.der"}}

	got := ClimbChain(chain, time.Second, 1, nil)
	if len(got) != 2 {
		t.Fatalf("got %d certs, want E9 + ISRG Root X2", len(got))
	}
	parent := got[1].Cert
	if parent == nil {
		t.Fatal("missing parent cert")
	}
	if parent.Subject.CommonName != "ISRG Root X2" {
		t.Fatalf("parent CN = %q", parent.Subject.CommonName)
	}
	if e9.CheckSignatureFrom(parent) != nil {
		t.Fatalf("climbed parent does not sign E9: %v", e9.CheckSignatureFrom(parent))
	}
	if parent.SerialNumber.Cmp(realRoot.SerialNumber) != 0 {
		t.Fatalf("selected serial %s, want pinned root %s", parent.SerialNumber, realRoot.SerialNumber)
	}
	if got[1].Source.Format != source.FormatPKCS7 {
		t.Fatalf("parent format = %q, want PKCS#7", got[1].Source.Format)
	}
	if got[1].Source.Type != source.Extracted {
		t.Fatalf("parent source type = %q, want extracted", got[1].Source.Type)
	}
}

func TestFetchParentViaCAIssuers_lePKCS7Bundle_selectsSigningParent(t *testing.T) {
	e9, _ := leIssuerBundle(t)
	got, info, url, err := FetchParentViaCAIssuers(e9, time.Second, nil)
	if err != nil {
		t.Fatalf("FetchParentViaCAIssuers: %v", err)
	}
	if got == nil {
		t.Fatal("expected ISRG Root X2 from PKCS#7 bundle")
	}
	if got.Subject.CommonName != "ISRG Root X2" {
		t.Fatalf("issuer CN = %q", got.Subject.CommonName)
	}
	if e9.CheckSignatureFrom(got) != nil {
		t.Fatalf("issuer does not sign E9: %v", e9.CheckSignatureFrom(got))
	}
	if url != e9.IssuingCertificateURL[0] {
		t.Fatalf("url = %q", url)
	}
	if info.Format != source.FormatPKCS7 {
		t.Fatalf("format = %q, want PKCS#7", info.Format)
	}
}

// leIssuerBundle returns E9 with its CA Issuers location pointing at a
// PKCS#7 bundle that lists an impostor before the pinned ISRG Root X2, and the
// pinned root.
func leIssuerBundle(t *testing.T) (*zx509.Certificate, *zx509.Certificate) {
	t.Helper()
	e9 := readLEFixtureCert(t, "e9.der")
	realRootDER := readLEFixtureCertDER(t, "isrg-root-x2.der")
	realRoot := testpki.ParseZCrypto(t, realRootDER)
	if e9.CheckSignatureFrom(realRoot) != nil {
		t.Fatal("fixture: E9 must be signed by pinned ISRG Root X2")
	}

	// The impostor has the subject and key identifier of E9's issuer but a
	// different key, so it must not be chosen while the real root is present.
	impostor := testpki.Issue(t, "ISRG Root X2", nil, testpki.CA(), testpki.Serial(0xbadc0de),
		testpki.SubjectKeyID(append([]byte(nil), e9.AuthorityKeyId...)),
		testpki.Validity(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)),
		testpki.Mutate(func(template *x509.Certificate) {
			template.Subject.Country = []string{"US"}
			template.Subject.Organization = []string{"Internet Security Research Group"}
		}))
	if impostor.Cert.Subject.String() != e9.Issuer.String() {
		t.Fatalf("impostor subject %q != E9 issuer %q", impostor.Cert.Subject, e9.Issuer)
	}
	if e9.CheckSignatureFrom(impostor.Cert) == nil {
		t.Fatal("impostor must not cryptographically sign E9")
	}

	pkcs7DER, err := aia.BuildCertsOnlyPKCS7(impostor.DER, realRootDER)
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7: %v", err)
	}
	if _, format, err := aia.ParseIssuerResponse(pkcs7DER); err != nil {
		t.Fatalf("ParseIssuerResponse: %v", err)
	} else if format != source.FormatPKCS7 {
		t.Fatalf("format = %q, want PKCS#7", format)
	}
	e9.IssuingCertificateURL = []string{testpki.Serve(t, pkcs7DER)}
	return e9, realRoot
}

func readLEFixtureCert(t *testing.T, name string) *zx509.Certificate {
	t.Helper()
	der := readLEFixtureCertDER(t, name)
	cert, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return cert
}

func readLEFixtureCertDER(t *testing.T, name string) []byte {
	t.Helper()
	for _, base := range []string{
		filepath.Join("testdata", "letsencrypt"),
		testfiles.CRLTestdata("letsencrypt"),
	} {
		path := filepath.Join(base, name)
		der, err := os.ReadFile(path)
		if err == nil {
			return der
		}
	}
	t.Fatalf("read LE fixture %s from cert or crl testdata", name)
	return nil
}
