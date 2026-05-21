package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/aia"
	"github.com/cavoq/PCL/internal/source"
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
	e9 := readLEFixtureCert(t, "e9.der")
	realRootDER := readLEFixtureCertDER(t, "isrg-root-x2.der")
	realRoot, err := zx509.ParseCertificate(realRootDER)
	if err != nil {
		t.Fatalf("parse ISRG Root X2: %v", err)
	}
	if e9.CheckSignatureFrom(realRoot) != nil {
		t.Fatal("fixture: E9 must be signed by pinned ISRG Root X2")
	}

	impostorDER := leISRGRootX2ImpostorDER(t, e9.AuthorityKeyId)
	impostor, err := zx509.ParseCertificate(impostorDER)
	if err != nil {
		t.Fatalf("parse impostor: %v", err)
	}
	if impostor.Subject.String() != e9.Issuer.String() {
		t.Fatalf("impostor subject %q != E9 issuer %q", impostor.Subject, e9.Issuer)
	}
	if e9.CheckSignatureFrom(impostor) == nil {
		t.Fatal("impostor must not cryptographically sign E9")
	}

	pkcs7DER, err := aia.BuildCertsOnlyPKCS7(impostorDER, realRootDER)
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7: %v", err)
	}
	if _, format, err := aia.ParseIssuerResponse(pkcs7DER); err != nil {
		t.Fatalf("ParseIssuerResponse: %v", err)
	} else if format != source.FormatPKCS7 {
		t.Fatalf("format = %q, want PKCS#7", format)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(pkcs7DER)
	}))
	defer server.Close()

	e9.IssuingCertificateURL = []string{server.URL}
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
	if got[1].Format != source.FormatPKCS7 {
		t.Fatalf("parent format = %q, want PKCS#7", got[1].Format)
	}
	if got[1].Source.Type != source.Extracted {
		t.Fatalf("parent source type = %q, want extracted", got[1].Source.Type)
	}
}

func TestFetchParentViaCAIssuers_lePKCS7Bundle_selectsSigningParent(t *testing.T) {
	e9 := readLEFixtureCert(t, "e9.der")
	realRootDER := readLEFixtureCertDER(t, "isrg-root-x2.der")
	impostorDER := leISRGRootX2ImpostorDER(t, e9.AuthorityKeyId)

	pkcs7DER, err := aia.BuildCertsOnlyPKCS7(impostorDER, realRootDER)
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(pkcs7DER)
	}))
	defer server.Close()

	e9.IssuingCertificateURL = []string{server.URL}
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
	if url != server.URL {
		t.Fatalf("url = %q", url)
	}
	if info.Format != source.FormatPKCS7 {
		t.Fatalf("format = %q, want PKCS#7", info.Format)
	}
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
		filepath.Join("..", "crl", "testdata", "letsencrypt"),
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

// leISRGRootX2ImpostorDER is a self-signed cert with the same subject and SKI as
// E9's issuer hint but a different key — it must not be chosen when the real root
// is present in the PKCS#7 bundle.
func leISRGRootX2ImpostorDER(t *testing.T, authorityKeyId []byte) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0xbadc0de),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Internet Security Research Group"},
			CommonName:   "ISRG Root X2",
		},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          append([]byte(nil), authorityKeyId...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create impostor: %v", err)
	}
	return der
}
