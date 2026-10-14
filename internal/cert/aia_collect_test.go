package cert

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
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
	root, rootURL := servedCA(t, "Root CA")
	inter := testpki.Issue(t, "Intermediate CA", root, testpki.CA(), testpki.Serial(10),
		testpki.SubjectKeyID([]byte{0x03, 0x04}), testpki.IssuingCertificateURLs(rootURL))
	leaf := aiaChild("subscriber", inter.Cert, testpki.Serve(t, inter.DER))

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
	parent, url := servedCA(t, "Parent CA")
	child := aiaChild("leaf.example", parent.Cert, url)

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
	if got[1].Subject.CommonName != "Parent CA" {
		t.Fatalf("second cert CN = %q, want Parent CA", got[1].Subject.CommonName)
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
	parent, serverURL := servedCA(t, "Issuer CA")
	child := aiaChild("subscriber.example", parent.Cert, serverURL)

	got, info, url, err := FetchParentViaCAIssuers(child, time.Second, nil)
	if err != nil {
		t.Fatalf("FetchParentViaCAIssuers() error: %v", err)
	}
	if got == nil || got.Subject.CommonName != "Issuer CA" {
		t.Fatalf("issuer = %v, want Issuer CA", got)
	}
	if url != serverURL {
		t.Fatalf("url = %q, want %q", url, serverURL)
	}
	if info.Format != source.FormatDER {
		t.Fatalf("format = %q, want DER", info.Format)
	}
}

func TestFetchParentViaCAIssuers_successPEM(t *testing.T) {
	parent := testpki.Issue(t, "PEM CA", nil, testpki.CA())
	child := aiaChild("leaf.pem.test", parent.Cert, testpki.Serve(t, testpki.PEM("CERTIFICATE", parent.DER)))

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

func TestFetchParentViaCAIssuers_returnsNilWhenBundleUnrelated(t *testing.T) {
	issuer := testpki.Issue(t, "Issuing CA", nil, testpki.CA())
	unrelated := testpki.Issue(t, "Unrelated CA", nil, testpki.CA(), testpki.Serial(99),
		testpki.SubjectKeyID([]byte{0xff, 0xfe}))
	leaf := testpki.Issue(t, "leaf.example", issuer, testpki.Serial(2),
		testpki.IssuingCertificateURLs(testpki.Serve(t, unrelated.DER))).Cert

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
	seen := NewCertificateSet(&zx509.Certificate{SerialNumber: big.NewInt(1)})

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
	if !seen.Contains(target) || seen.Contains(other) {
		t.Fatal("seen set should record the target but not candidates after it")
	}
}

func TestAppendUniqueCandidates_keepsSameSerialFromDifferentIssuers(t *testing.T) {
	first := &zx509.Certificate{
		Issuer:                  zpkix.Name{CommonName: "Issuer A"},
		SerialNumber:            big.NewInt(7),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
	}
	second := &zx509.Certificate{
		Issuer:                  zpkix.Name{CommonName: "Issuer B"},
		SerialNumber:            big.NewInt(7),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
	}
	added, stop := appendUniqueCandidates(NewCertificateSet(), nil, []*zx509.Certificate{first, second}, nil)
	if stop || len(added) != 2 || added[0] != first || added[1] != second {
		t.Fatalf("appendUniqueCandidates() = (%v, %v), want both issuer-scoped serials", added, stop)
	}
}

func TestAppendUniqueCandidates_skipsInvalidCandidates(t *testing.T) {
	seen := NewCertificateSet()
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

// servedCA issues a self-signed CA and serves its DER encoding.
func servedCA(t *testing.T, name string) (*testpki.Certificate, string) {
	t.Helper()
	ca := testpki.Issue(t, name, nil, testpki.CA())
	return ca, testpki.Serve(t, ca.DER)
}

// aiaChild is an unsigned certificate naming parent as its issuer, with url as
// its CA Issuers location.
func aiaChild(name string, parent *zx509.Certificate, url string) *zx509.Certificate {
	return &zx509.Certificate{
		Subject:               zpkix.Name{CommonName: name},
		Issuer:                parent.Subject,
		SerialNumber:          big.NewInt(2),
		IssuingCertificateURL: []string{url},
	}
}

func TestClimbChain_fetchesParent(t *testing.T) {
	parent, url := servedCA(t, "Climb Parent")
	leaf := aiaChild("climb-leaf.example", parent.Cert, url)

	chain := []*Info{{Cert: leaf, FilePath: "leaf.pem"}}
	got := ClimbChain(chain, time.Second, 1, nil)
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2", len(got))
	}
	if got[1].Cert.Subject.CommonName != "Climb Parent" {
		t.Fatalf("parent CN = %q", got[1].Cert.Subject.CommonName)
	}
	if got[1].FilePath != url {
		t.Fatalf("parent source path = %q", got[1].FilePath)
	}
}

func TestClimbChain_detectsCircularReference(t *testing.T) {
	parent, url := servedCA(t, "Circle CA")
	leaf := aiaChild("circle-leaf", parent.Cert, url)

	// Parent is already in chain; climbing from leaf re-fetches the same CA serial.
	chain := []*Info{
		{Cert: parent.Cert},
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
