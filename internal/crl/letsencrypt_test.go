package crl

import (
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func readLetsEncryptFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "letsencrypt", name))
	if err != nil {
		t.Fatalf("read letsencrypt fixture %s: %v", name, err)
	}
	return data
}

func parseLetsEncryptRootX1CRL(t *testing.T) *x509.RevocationList {
	t.Helper()
	revocationList, err := ParseCRL(readLetsEncryptFixture(t, "isrg-root-x1.crl"))
	if err != nil {
		t.Fatalf("parse ISRG Root X1 CRL: %v", err)
	}
	return revocationList
}

func parseLetsEncryptRootX1Cert(t *testing.T) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(readLetsEncryptFixture(t, "isrgrootx1.der"))
	if err != nil {
		t.Fatalf("parse ISRG Root X1 cert: %v", err)
	}
	return c
}

// TestLetsEncrypt_ISRGRootX1_isOtherCRLProfile documents LE root CRLs: long
// nextUpdate window must classify as other CRL (isCACRL true), not subscriber.
func TestLetsEncrypt_ISRGRootX1_isOtherCRLProfile(t *testing.T) {
	revocationList := parseLetsEncryptRootX1CRL(t)

	window := revocationList.NextUpdate.Sub(revocationList.ThisUpdate)
	if window <= subscriberCRLMaxInterval {
		t.Fatalf("fixture window = %v, want > %v (refresh CRL if LE changed policy)", window, subscriberCRLMaxInterval)
	}
	if !isCACRL(revocationList, nil) {
		t.Fatal("ISRG Root X1 CRL should be isCACRL true via validity inference")
	}

	tree := BuildTreeWithChain(revocationList, nil)
	if tree.Children["isCACRL"].Value != true {
		t.Fatalf("tree isCACRL = %v, want true", tree.Children["isCACRL"].Value)
	}
}

// TestLetsEncrypt_ISRGRootX1_signingCertFromPool verifies the official root when
// it is present in the pool (signature path, not DN-only spoofing).
func TestLetsEncrypt_ISRGRootX1_signingCertFromPool(t *testing.T) {
	revocationList := parseLetsEncryptRootX1CRL(t)
	root := parseLetsEncryptRootX1Cert(t)

	if root.Subject.String() != revocationList.Issuer.String() {
		t.Fatalf("fixture mismatch: cert subject %q vs CRL issuer %q", root.Subject, revocationList.Issuer)
	}

	got := SigningCertFromPool(revocationList, []*x509.Certificate{root})
	if got == nil {
		t.Fatal("expected ISRG Root X1 from pool")
	}
	if got != root {
		t.Fatalf("SigningCertFromPool() = %q, want ISRG Root X1", got.Subject.CommonName)
	}
	if err := revocationList.CheckSignatureFrom(got); err != nil {
		t.Fatalf("CRL signature must verify with official root: %v", err)
	}
}

// TestLetsEncrypt_ISRGRootX1_chainWithoutRootStillOtherCRL models validating a
// subscriber chain that does not include the root: BR other-CRL inference must
// still apply (this was the misclassification risk for long-validity CDP CRLs).
func TestLetsEncrypt_ISRGRootX1_chainWithoutRootStillOtherCRL(t *testing.T) {
	revocationList := parseLetsEncryptRootX1CRL(t)
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		Issuer:       pkix.Name{CommonName: "R13"},
		SerialNumber: big.NewInt(1),
	}
	intermediate := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "R13"},
		IsCA:         true,
		SerialNumber: big.NewInt(2),
	}

	pool := []*x509.Certificate{leaf, intermediate}
	if !isCACRL(revocationList, pool) {
		t.Fatal("expected isCACRL true without root in pool when validity > 10 days")
	}
}

// TestLetsEncrypt_ISRGRootX1_resolveIssuerCerts_skipsAIAWhenRootPresent ensures
// we do not network-fetch when the chain already contains the CRL signer.
func TestLetsEncrypt_ISRGRootX1_resolveIssuerCerts_skipsAIAWhenRootPresent(t *testing.T) {
	revocationList := parseLetsEncryptRootX1CRL(t)
	root := parseLetsEncryptRootX1Cert(t)
	chain := []*cert.Info{
		{Cert: &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}}},
		{Cert: root},
	}

	pool := ResolveIssuerCerts(chain, revocationList, time.Second, 2, nil)
	if len(pool) != 2 {
		t.Fatalf("pool len = %d, want 2 (no AIA expansion)", len(pool))
	}
	if SigningCertFromPool(revocationList, pool) != root {
		t.Fatal("expected pool to identify ISRG Root X1 as signer")
	}
}

// TestLetsEncrypt_subscriberCRL_whenURLAvailable pins a live LE intermediate CRL
// (≤10 day nextUpdate) once published. As of 2026-05, e9.c.lencr.org / r14.c.lencr.org
// return 404 outside rotation; set PCL_LE_SUBSCRIBER_CRL_URL to enable this test.
func TestLetsEncrypt_subscriberCRL_whenURLAvailable(t *testing.T) {
	url := os.Getenv("PCL_LE_SUBSCRIBER_CRL_URL")
	if url == "" {
		t.Skip("set PCL_LE_SUBSCRIBER_CRL_URL to a downloadable LE intermediate subscriber CRL (e.g. when e9.c.lencr.org serves 200)")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("fetch subscriber CRL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("subscriber CRL URL returned %s: %s", resp.Status, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read CRL body: %v", err)
	}
	revocationList, err := ParseCRL(body)
	if err != nil {
		t.Fatalf("parse subscriber CRL: %v", err)
	}

	window := revocationList.NextUpdate.Sub(revocationList.ThisUpdate)
	if window > subscriberCRLMaxInterval {
		t.Fatalf("subscriber CRL window = %v, want ≤ %v", window, subscriberCRLMaxInterval)
	}
	if isCACRL(revocationList, nil) {
		t.Fatal("subscriber CRL should not classify as other CRL (isCACRL false)")
	}
}
