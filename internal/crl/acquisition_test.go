package crl

import (
	"context"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestFetchSessionCachesURLSuccessAndDeduplicatesObjects(t *testing.T) {
	der := makeAcquisitionCRL(t, 1, nil)
	firstURL, firstHits := testpki.ServeCounted(t, der)
	secondURL, secondHits := testpki.ServeCounted(t, der)

	session := NewFetchSession(FetchConfig{Timeout: time.Second})
	firstResult, err := session.Fetch(firstURL)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	again, err := session.Fetch(firstURL + "#ignored")
	if err != nil {
		t.Fatalf("cached fetch: %v", err)
	}
	if firstResult == again || firstResult.Hash != again.Hash || firstHits.Load() != 1 {
		t.Fatalf("same canonical URL was not cached as snapshots: first=%p again=%p hits=%d", firstResult, again, firstHits.Load())
	}

	results, errs := session.FetchAll([]string{firstURL, secondURL, secondURL})
	if len(errs) != 0 {
		t.Fatalf("FetchAll errors: %v", errs)
	}
	if len(results) != 1 || results[0].Hash != firstResult.Hash {
		t.Fatalf("FetchAll returned %#v, want one deduplicated object", results)
	}
	if firstHits.Load() != 1 || secondHits.Load() != 1 {
		t.Fatalf("server hits = (%d,%d), want (1,1)", firstHits.Load(), secondHits.Load())
	}
	if len(firstResult.Origins) != 1 || firstResult.Origins[0] != firstURL {
		t.Fatalf("published snapshot was mutated: origins = %v", firstResult.Origins)
	}
	if len(results[0].Origins) != 2 || results[0].Origins[0] != firstURL || results[0].Origins[1] != secondURL {
		t.Fatalf("deduplicated origins = %v, want both URLs", results[0].Origins)
	}
	if results[0].Format != source.FormatDER || results[0].Source.Format != source.FormatDER {
		t.Fatalf("download format = (%q,%q), want DER", results[0].Format, results[0].Source.Format)
	}
}

func TestFetchSessionCachesFailures(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	session := NewFetchSession(FetchConfig{Timeout: time.Second})
	for i := 0; i < 2; i++ {
		if _, err := session.Fetch(server.URL); err == nil {
			t.Fatal("failed response unexpectedly succeeded")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("failed URL fetched %d times, want once", hits.Load())
	}
}

func TestFetchSessionRejectsPEMOversizeAndUnsupportedSchemes(t *testing.T) {
	der := makeAcquisitionCRL(t, 1, nil)
	pemBody := testpki.PEM("X509 CRL", der)

	t.Run("PEM", func(t *testing.T) {
		serverURL := testpki.Serve(t, pemBody)
		_, err := NewFetchSession(FetchConfig{Timeout: time.Second}).Fetch(serverURL)
		if err == nil || !strings.Contains(err.Error(), "DER-encoded CRL") {
			t.Fatalf("PEM error = %v", err)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		serverURL, hits := testpki.ServeCounted(t, make([]byte, 33))
		session := NewFetchSession(FetchConfig{Timeout: time.Second, MaxResponseBytes: 32})
		for i := 0; i < 2; i++ {
			_, err := session.Fetch(serverURL)
			if err == nil || !strings.Contains(err.Error(), "exceeds 32 bytes") {
				t.Fatalf("oversize error = %v", err)
			}
		}
		if hits.Load() != 1 {
			t.Fatalf("oversize response fetched %d times, want cached failure", hits.Load())
		}
	})

	t.Run("custom retriever oversize", func(t *testing.T) {
		retriever := &staticRetriever{body: make([]byte, 33)}
		session := NewFetchSession(FetchConfig{
			MaxResponseBytes: 32,
			Retriever:        retriever,
		})
		for i := 0; i < 2; i++ {
			_, err := session.Fetch("https://example.test/list.crl")
			if err == nil || !strings.Contains(err.Error(), "exceeds 32 bytes") {
				t.Fatalf("custom retriever oversize error = %v", err)
			}
		}
		if retriever.calls.Load() != 1 {
			t.Fatalf("custom retriever called %d times, want cached failure", retriever.calls.Load())
		}
	})

	t.Run("trailing data", func(t *testing.T) {
		retriever := &staticRetriever{body: append(append([]byte(nil), der...), 0)}
		_, err := NewFetchSession(FetchConfig{Retriever: retriever}).Fetch(
			"https://example.test/list.crl",
		)
		if err == nil || !strings.Contains(err.Error(), "outside the CRL") {
			t.Fatalf("trailing-data error = %v", err)
		}
	})

	t.Run("scheme", func(t *testing.T) {
		retriever := &countingRetriever{}
		session := NewFetchSession(FetchConfig{Retriever: retriever})
		for _, resourceURL := range []string{"file:///tmp/list.crl", "ftp://example.test/list.crl"} {
			if _, err := session.Fetch(resourceURL); err == nil || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("scheme error for %s = %v", resourceURL, err)
			}
		}
		if retriever.calls.Load() != 0 {
			t.Fatalf("retriever called %d times for unsupported schemes", retriever.calls.Load())
		}
	})
}

func TestFetchSessionDiscoversCertificateAndCRLFreshest(t *testing.T) {
	directDeltaDER := makeAcquisitionCRL(t, 2, []cryptopkix.Extension{deltaCRLIndicator(t, 1)})
	directDeltaURL, directDeltaHits := testpki.ServeCounted(t, directDeltaDER)

	secondDeltaDER := makeAcquisitionCRL(t, 3, []cryptopkix.Extension{deltaCRLIndicator(t, 1)})
	secondDeltaURL, secondDeltaHits := testpki.ServeCounted(t, secondDeltaDER)

	baseDER := makeAcquisitionCRL(t, 1, []cryptopkix.Extension{
		freshestCRL(t, secondDeltaURL),
	})
	baseURL, baseHits := testpki.ServeCounted(t, baseDER)

	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    zasn1.ObjectIdentifier{2, 5, 29, 31},
				Value: distributionPointsURIs(t, baseURL),
			},
			{
				Id:    zasn1.ObjectIdentifier{2, 5, 29, 46},
				Value: distributionPointsURIs(t, directDeltaURL),
			},
		},
	}
	chain := []*cert.Info{{Cert: certificate}, {Cert: certificate}}
	results := NewFetchSession(FetchConfig{Timeout: time.Second}).FetchForChain(chain, nil)
	if len(results) != 3 {
		t.Fatalf("fetched %d unique CRLs, want base plus two deltas", len(results))
	}
	if baseHits.Load() != 1 || directDeltaHits.Load() != 1 || secondDeltaHits.Load() != 1 {
		t.Fatalf(
			"request counts = base:%d certificate-freshest:%d CRL-freshest:%d, want all 1",
			baseHits.Load(),
			directDeltaHits.Load(),
			secondDeltaHits.Load(),
		)
	}
}

func TestFetchSessionNeverFollowsFreshestOnDelta(t *testing.T) {
	trapDER := makeAcquisitionCRL(t, 9, nil)
	trapURL, trapHits := testpki.ServeCounted(t, trapDER)

	deltaDER := makeAcquisitionCRL(t, 2, []cryptopkix.Extension{
		deltaCRLIndicator(t, 1),
		freshestCRL(t, trapURL),
	})
	deltaURL := testpki.Serve(t, deltaDER)

	chain := []*cert.Info{{Cert: &x509.Certificate{CRLDistributionPoints: []string{deltaURL}}}}
	results := NewFetchSession(FetchConfig{Timeout: time.Second}).FetchForChain(chain, nil)
	if len(results) != 1 {
		t.Fatalf("fetched %d CRLs, want only the delta", len(results))
	}
	if trapHits.Load() != 0 {
		t.Fatalf("followed forbidden Freshest CRL on delta %d times", trapHits.Load())
	}
}

func TestCertificateDistributionPointURLsPreservesDuplicateError(t *testing.T) {
	extension := pkix.Extension{
		Id:    zasn1.ObjectIdentifier{2, 5, 29, 31},
		Value: distributionPointsURIs(t, "https://example.test/list.crl"),
	}
	certificate := &x509.Certificate{
		Extensions:            []pkix.Extension{extension, extension},
		CRLDistributionPoints: []string{"https://example.test/typed-fallback.crl"},
	}

	urls, errs := certificateDistributionPointURLs(certificate)
	if len(urls) != 0 {
		t.Fatalf("certificateDistributionPointURLs() URLs = %v, want none", urls)
	}
	if len(errs) != 1 {
		t.Fatalf("certificateDistributionPointURLs() errors = %v, want one", errs)
	}
	const want = "cannot decode certificate extension 2.5.29.31 for CRL acquisition: extension 2.5.29.31 appears 2 times"
	if errs[0].Error() != want {
		t.Fatalf("certificateDistributionPointURLs() error = %q, want %q", errs[0], want)
	}
}

type countingRetriever struct {
	calls atomic.Int32
}

func (retriever *countingRetriever) Retrieve(context.Context, string, int64) ([]byte, error) {
	retriever.calls.Add(1)
	return nil, nil
}

type staticRetriever struct {
	body  []byte
	calls atomic.Int32
}

func (retriever *staticRetriever) Retrieve(context.Context, string, int64) ([]byte, error) {
	retriever.calls.Add(1)
	return retriever.body, nil
}

func makeAcquisitionCRL(t *testing.T, number int64, extensions []cryptopkix.Extension) []byte {
	t.Helper()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	issuer := testpki.IssueWithKey(t, "Acquisition Test CA", testpki.ECDSAKey(t), nil, testpki.CA(),
		testpki.Serial(number+100), testpki.SubjectKeyID([]byte{0x01, 0x02, 0x03}),
		testpki.Validity(now.Add(-time.Hour), now.Add(24*time.Hour)))
	return issuer.RevocationList(t, &cryptox509.RevocationList{
		Number:          big.NewInt(number),
		ThisUpdate:      now.Add(-time.Hour),
		NextUpdate:      now.Add(time.Hour),
		ExtraExtensions: extensions,
	})
}
