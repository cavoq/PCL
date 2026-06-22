package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/source"
	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
)

func TestCollectViaCAIssuers_skipsNilFrontierCert(t *testing.T) {
	got := CollectViaCAIssuers([]*zx509.Certificate{nil}, AIACollectConfig{
		Timeout:  time.Second,
		MaxDepth: 1,
	})
	if len(got) != 1 || got[0] != nil {
		t.Fatalf("got %v, want nil seed preserved", got)
	}
}

func TestCollectViaCAIssuers_twoHopBFS(t *testing.T) {
	rootDER, root, rootKey := testParentChildPair(t, "Root CA", "unused-leaf")
	rootServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(rootDER)
	}))
	defer rootServer.Close()

	interDER, inter := testSignedChildCA(t, root, rootKey, "Intermediate CA", []byte{0x03, 0x04}, []string{rootServer.URL})
	interServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(interDER)
	}))
	defer interServer.Close()

	leaf := &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: "subscriber"},
		Issuer:                inter.Subject,
		SerialNumber:          big.NewInt(3),
		IssuingCertificateURL: []string{interServer.URL},
	}

	got := CollectViaCAIssuers([]*zx509.Certificate{leaf}, AIACollectConfig{
		Timeout:  time.Second,
		MaxDepth: 3,
	})
	if len(got) != 3 {
		t.Fatalf("got %d certs, want leaf + intermediate + root", len(got))
	}
}

func TestCollectViaCAIssuers_noFetchWhenDisabled(t *testing.T) {
	seed := []*zx509.Certificate{{
		Subject:      zpkix.Name{CommonName: "Leaf"},
		SerialNumber: big.NewInt(1),
	}}
	got := CollectViaCAIssuers(seed, AIACollectConfig{})
	if len(got) != 1 || got[0] != seed[0] {
		t.Fatalf("CollectViaCAIssuers() = %v, want seed only", got)
	}
}

func TestCollectViaCAIssuers_fetchesAndStops(t *testing.T) {
	parentDER, parent, _ := testParentChildPair(t, "Parent CA", "leaf.example")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	child := &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: "leaf.example"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}

	var buf bytes.Buffer
	got := CollectViaCAIssuers([]*zx509.Certificate{child}, AIACollectConfig{
		Timeout:  time.Second,
		MaxDepth: 1,
		Warn:     &buf,
		StopWhen: func(c *zx509.Certificate) bool {
			return c != nil && c.Subject.CommonName == "Parent CA"
		},
	})

	if len(got) != 2 {
		t.Fatalf("got %d certs, want seed + parent", len(got))
	}
	if got[1].Subject.CommonName != parent.Subject.CommonName {
		t.Fatalf("second cert CN = %q, want %q", got[1].Subject.CommonName, parent.Subject.CommonName)
	}
}

func TestCollectViaCAIssuers_warnsOnFetchError(t *testing.T) {
	child := &zx509.Certificate{
		SerialNumber:          big.NewInt(1),
		IssuingCertificateURL: []string{"http://127.0.0.1:1/"},
	}

	var buf bytes.Buffer
	got := CollectViaCAIssuers([]*zx509.Certificate{child}, AIACollectConfig{
		Timeout:  50 * time.Millisecond,
		MaxDepth: 1,
		Warn:     &buf,
	})
	if len(got) != 1 {
		t.Fatalf("got %d certs, want seed only", len(got))
	}
	if buf.Len() == 0 {
		t.Fatal("expected fetch warning")
	}
}

func TestFetchParentViaCAIssuers_noAIA(t *testing.T) {
	child := &zx509.Certificate{
		Subject:      zpkix.Name{CommonName: "Leaf"},
		SerialNumber: big.NewInt(1),
	}
	cert, info, url, err := FetchParentViaCAIssuers(child, time.Second, nil)
	if err != nil || cert != nil || url != "" || info.Type != "" {
		t.Fatalf("FetchParentViaCAIssuers() = (%v, %v, %q, %v), want nil,nil,\"\",nil", cert, info, url, err)
	}
}

func TestFetchParentViaCAIssuers_successDER(t *testing.T) {
	parentDER, parent, _ := testParentChildPair(t, "Issuer CA", "subscriber.example")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	child := &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: "subscriber.example"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}

	got, info, url, err := FetchParentViaCAIssuers(child, time.Second, nil)
	if err != nil {
		t.Fatalf("FetchParentViaCAIssuers() error: %v", err)
	}
	if got == nil || got.Subject.CommonName != "Issuer CA" {
		t.Fatalf("issuer = %v, want Issuer CA", got)
	}
	if url != server.URL {
		t.Fatalf("url = %q, want %q", url, server.URL)
	}
	if info.Format != source.FormatDER {
		t.Fatalf("format = %q, want DER", info.Format)
	}
}

func TestFetchParentViaCAIssuers_successPEM(t *testing.T) {
	parentDER, parent, _ := testParentChildPair(t, "PEM CA", "leaf.pem.test")
	pemBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parentDER})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(pemBody)
	}))
	defer server.Close()

	child := &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: "leaf.pem.test"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}

	var buf bytes.Buffer
	got, info, _, err := FetchParentViaCAIssuers(child, time.Second, &buf)
	if err != nil {
		t.Fatalf("FetchParentViaCAIssuers() error: %v", err)
	}
	if got == nil {
		t.Fatal("expected issuer certificate")
	}
	if info.Format != source.FormatPEM {
		t.Fatalf("format = %q, want PEM", info.Format)
	}
	if info.Description != "downloaded PEM" {
		t.Fatalf("description = %q", info.Description)
	}
	if buf.Len() == 0 {
		t.Fatal("expected PEM format warning")
	}
}

func TestFetchParentViaCAIssuers_emptyResults(t *testing.T) {
	child := &zx509.Certificate{
		IssuingCertificateURL: []string{"http://127.0.0.1:1/"},
	}
	_, _, url, err := FetchParentViaCAIssuers(child, 50*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected fetch error when all URLs fail")
	}
	if url != "http://127.0.0.1:1/" {
		t.Fatalf("url = %q", url)
	}
}

func TestFetchParentViaCAIssuers_returnsNilWhenBundleUnrelated(t *testing.T) {
	leaf := testSignedLeafZX509(t)
	unrelatedDER := testParentDEROnly(t, "Unrelated CA", []byte{0xff, 0xfe})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(unrelatedDER)
	}))
	defer server.Close()

	leaf.IssuingCertificateURL = []string{server.URL}
	var buf bytes.Buffer
	got, _, _, err := FetchParentViaCAIssuers(leaf, time.Second, &buf)
	if err != nil {
		t.Fatalf("FetchParentViaCAIssuers() error: %v", err)
	}
	if got != nil {
		t.Fatalf("issuer = %v, want nil when bundle does not match leaf", got)
	}
	if buf.Len() == 0 {
		t.Fatal("expected warning when CA Issuers response has no matching issuer")
	}
}

func TestFetchParentViaCAIssuers_fetchError(t *testing.T) {
	child := &zx509.Certificate{
		IssuingCertificateURL: []string{"http://127.0.0.1:1/"},
	}
	_, _, url, err := FetchParentViaCAIssuers(child, 50*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected fetch error")
	}
	if url != "http://127.0.0.1:1/" {
		t.Fatalf("url = %q", url)
	}
}

func TestWarnPKCS7Bundle(t *testing.T) {
	child := &zx509.Certificate{
		Issuer: zpkix.Name{CommonName: "Expected Issuer"},
	}
	candidates := []*zx509.Certificate{
		{Subject: zpkix.Name{CommonName: "Other 1"}, SerialNumber: big.NewInt(1)},
		{Subject: zpkix.Name{CommonName: "Other 2"}, SerialNumber: big.NewInt(2)},
	}
	var buf bytes.Buffer
	warnPKCS7Bundle(&buf, child, candidates)
	if buf.Len() == 0 {
		t.Fatal("expected PKCS#7 bundle warning")
	}
}

func TestNormalizeIssuerSourceInfo(t *testing.T) {
	pkcs7 := normalizeIssuerSourceInfo(source.Info{Format: source.FormatPKCS7, URL: "https://example/aia"})
	if pkcs7.Type != source.Extracted || pkcs7.Description != "extracted from PKCS#7" {
		t.Fatalf("PKCS#7 info = %+v", pkcs7)
	}

	pemInfo := normalizeIssuerSourceInfo(source.Info{Format: source.FormatPEM, URL: "https://example/aia"})
	if pemInfo.Description != "downloaded PEM" {
		t.Fatalf("PEM info = %+v", pemInfo)
	}
}

func TestAppendUniqueCandidates_stopWhen(t *testing.T) {
	target := &zx509.Certificate{
		Subject:      zpkix.Name{CommonName: "Target"},
		SerialNumber: big.NewInt(42),
	}
	other := &zx509.Certificate{
		Subject:      zpkix.Name{CommonName: "Other"},
		SerialNumber: big.NewInt(43),
	}
	seen := map[string]bool{"1": true}

	added, stop := appendUniqueCandidates(seen, nil, []*zx509.Certificate{
		{SerialNumber: big.NewInt(1)},
		target,
		other,
	}, func(c *zx509.Certificate) bool {
		return c == target
	})
	if !stop || len(added) != 1 || added[0] != target {
		t.Fatalf("appendUniqueCandidates() = (%v, %v), want ([target], true)", added, stop)
	}
	if !seen["42"] || seen["43"] {
		t.Fatalf("seen after stop = %v, want only target serial recorded", seen)
	}
}

func TestMarkSerialSeen(t *testing.T) {
	seen := map[string]bool{}
	cert := &zx509.Certificate{SerialNumber: big.NewInt(7)}
	if markSerialSeen(seen, cert) {
		t.Fatal("first mark should not be duplicate")
	}
	if !markSerialSeen(seen, cert) {
		t.Fatal("second mark should be duplicate")
	}
}

func TestMarkSerialSeen_nilCert(t *testing.T) {
	if markSerialSeen(map[string]bool{}, nil) {
		t.Fatal("nil cert should not count as duplicate")
	}
}

func TestAppendUniqueCandidates_skipsInvalidCandidates(t *testing.T) {
	seen := map[string]bool{}
	added, stop := appendUniqueCandidates(seen, nil, []*zx509.Certificate{
		nil,
		{Subject: zpkix.Name{CommonName: "no-serial"}},
	}, nil)
	if stop || len(added) != 0 {
		t.Fatalf("appendUniqueCandidates() = (%v, %v), want ([], false)", added, stop)
	}
}

func TestWarnPEMDownload(t *testing.T) {
	var buf bytes.Buffer
	warnPEMDownload(&buf, "https://example.com/ca.cer", source.FormatPEM)
	if buf.Len() == 0 {
		t.Fatal("expected PEM warning")
	}
}

func testSignedLeafZX509(t *testing.T) *zx509.Certificate {
	t.Helper()

	parentDER, _, key := testParentChildPair(t, "Issuing CA", "leaf.example")
	parentStd, err := x509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatalf("parse parent std: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		Issuer:       pkix.Name{CommonName: "Issuing CA"},
		NotBefore:    parentStd.NotBefore,
		NotAfter:     parentStd.NotAfter,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, parentStd, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := zx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func testParentDEROnly(t *testing.T, cn string, ski []byte) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create unrelated parent: %v", err)
	}
	return der
}

func testParentChildPair(t *testing.T, parentCN, childCN string) ([]byte, *zx509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	parentTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: parentCN},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02},
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, parentTemplate, parentTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parent, err := zx509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatalf("parse parent: %v", err)
	}

	childTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: childCN},
		Issuer:       pkix.Name{CommonName: parentCN},
		NotBefore:    parentTemplate.NotBefore,
		NotAfter:     parentTemplate.NotAfter,
	}
	_, err = x509.CreateCertificate(rand.Reader, childTemplate, parentTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	return parentDER, parent, key
}

func testSignedChildCA(t *testing.T, parent *zx509.Certificate, parentKey *rsa.PrivateKey, cn string, ski []byte, aiaURLs []string) ([]byte, *zx509.Certificate) {
	t.Helper()

	parentStd, err := x509.ParseCertificate(parent.Raw)
	if err != nil {
		t.Fatalf("parse parent raw: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                parentStd.Subject,
		NotBefore:             parentStd.NotBefore,
		NotAfter:              parentStd.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
		IssuingCertificateURL: aiaURLs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentStd, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	parsed, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	return der, parsed
}

func TestClimbChain_fetchesParent(t *testing.T) {
	parentDER, parent, _ := testParentChildPair(t, "Climb Parent", "climb-leaf.example")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	leaf := &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: "climb-leaf.example"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}

	chain := []*Info{{Cert: leaf, FilePath: "leaf.pem"}}
	got := ClimbChain(chain, time.Second, 1, nil)
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2", len(got))
	}
	if got[1].Cert.Subject.CommonName != "Climb Parent" {
		t.Fatalf("parent CN = %q", got[1].Cert.Subject.CommonName)
	}
	if got[1].FilePath != server.URL {
		t.Fatalf("parent source path = %q", got[1].FilePath)
	}
}

func TestClimbChain_detectsCircularReference(t *testing.T) {
	parentDER, parent, _ := testParentChildPair(t, "Circle CA", "circle-leaf")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(parentDER)
	}))
	defer server.Close()

	leaf := &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: "circle-leaf"},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{server.URL},
	}

	// Parent is already in chain; climbing from leaf re-fetches the same CA serial.
	chain := []*Info{
		{Cert: parent},
		{Cert: leaf},
	}
	var buf bytes.Buffer
	got := ClimbChain(chain, time.Second, 2, &buf)
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2 (no duplicate append)", len(got))
	}
	if buf.Len() == 0 {
		t.Fatal("expected circular reference warning")
	}
}
