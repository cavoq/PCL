package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/source"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestFetchSessionCachesURLSuccessAndDeduplicatesObjects(t *testing.T) {
	der := makeAcquisitionCRL(t, 1, nil)
	var firstHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		_, _ = w.Write(der)
	}))
	defer first.Close()
	var secondHits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		_, _ = w.Write(der)
	}))
	defer second.Close()

	session := NewFetchSession(FetchConfig{Timeout: time.Second})
	firstResult, err := session.Fetch(first.URL)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	again, err := session.Fetch(first.URL + "#ignored")
	if err != nil {
		t.Fatalf("cached fetch: %v", err)
	}
	if firstResult == again || firstResult.Hash != again.Hash || firstHits.Load() != 1 {
		t.Fatalf("same canonical URL was not cached as snapshots: first=%p again=%p hits=%d", firstResult, again, firstHits.Load())
	}

	results, errs := session.FetchAll([]string{first.URL, second.URL, second.URL})
	if len(errs) != 0 {
		t.Fatalf("FetchAll errors: %v", errs)
	}
	if len(results) != 1 || results[0].Hash != firstResult.Hash {
		t.Fatalf("FetchAll returned %#v, want one deduplicated object", results)
	}
	if firstHits.Load() != 1 || secondHits.Load() != 1 {
		t.Fatalf("server hits = (%d,%d), want (1,1)", firstHits.Load(), secondHits.Load())
	}
	if len(firstResult.Origins) != 1 || firstResult.Origins[0] != first.URL {
		t.Fatalf("published snapshot was mutated: origins = %v", firstResult.Origins)
	}
	if len(results[0].Origins) != 2 || results[0].Origins[0] != first.URL || results[0].Origins[1] != second.URL {
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
	pemBody := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})

	t.Run("PEM", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(pemBody)
		}))
		defer server.Close()
		_, err := NewFetchSession(FetchConfig{Timeout: time.Second}).Fetch(server.URL)
		if err == nil || !strings.Contains(err.Error(), "DER-encoded CRL") {
			t.Fatalf("PEM error = %v", err)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		var hits atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write(make([]byte, 33))
		}))
		defer server.Close()
		session := NewFetchSession(FetchConfig{Timeout: time.Second, MaxResponseBytes: 32})
		for i := 0; i < 2; i++ {
			_, err := session.Fetch(server.URL)
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
	directDeltaDER := makeAcquisitionCRL(t, 2, []cryptopkix.Extension{deltaIndicatorExtension()})
	var directDeltaHits atomic.Int32
	directDeltaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directDeltaHits.Add(1)
		_, _ = w.Write(directDeltaDER)
	}))
	defer directDeltaServer.Close()

	secondDeltaDER := makeAcquisitionCRL(t, 3, []cryptopkix.Extension{deltaIndicatorExtension()})
	var secondDeltaHits atomic.Int32
	secondDeltaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondDeltaHits.Add(1)
		_, _ = w.Write(secondDeltaDER)
	}))
	defer secondDeltaServer.Close()

	baseDER := makeAcquisitionCRL(t, 1, []cryptopkix.Extension{
		freshestExtension(distributionPointsForURL(t, secondDeltaServer.URL)),
	})
	var baseHits atomic.Int32
	baseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		baseHits.Add(1)
		_, _ = w.Write(baseDER)
	}))
	defer baseServer.Close()

	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    zasn1.ObjectIdentifier{2, 5, 29, 31},
				Value: distributionPointsForURL(t, baseServer.URL),
			},
			{
				Id:    zasn1.ObjectIdentifier{2, 5, 29, 46},
				Value: distributionPointsForURL(t, directDeltaServer.URL),
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
	var trapHits atomic.Int32
	trapDER := makeAcquisitionCRL(t, 9, nil)
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		trapHits.Add(1)
		_, _ = w.Write(trapDER)
	}))
	defer trap.Close()

	deltaDER := makeAcquisitionCRL(t, 2, []cryptopkix.Extension{
		deltaIndicatorExtension(),
		freshestExtension(distributionPointsForURL(t, trap.URL)),
	})
	delta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(deltaDER)
	}))
	defer delta.Close()

	chain := []*cert.Info{{Cert: &x509.Certificate{CRLDistributionPoints: []string{delta.URL}}}}
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
		Value: distributionPointsForURL(t, "https://example.test/list.crl"),
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CRL issuer key: %v", err)
	}
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	issuerTemplate := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(number + 100),
		Subject:               cryptopkix.Name{CommonName: "Acquisition Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03},
	}
	issuerDER, err := cryptox509.CreateCertificate(
		rand.Reader,
		issuerTemplate,
		issuerTemplate,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	issuer, err := cryptox509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse CRL issuer: %v", err)
	}
	der, err := cryptox509.CreateRevocationList(rand.Reader, &cryptox509.RevocationList{
		Number:          big.NewInt(number),
		ThisUpdate:      now.Add(-time.Hour),
		NextUpdate:      now.Add(time.Hour),
		ExtraExtensions: extensions,
	}, issuer, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}

func deltaIndicatorExtension() cryptopkix.Extension {
	return cryptopkix.Extension{
		Id:       stdasn1.ObjectIdentifier{2, 5, 29, 27},
		Critical: true,
		Value:    []byte{0x02, 0x01, 0x01},
	}
}

func freshestExtension(value []byte) cryptopkix.Extension {
	return cryptopkix.Extension{
		Id:    stdasn1.ObjectIdentifier{2, 5, 29, 46},
		Value: value,
	}
}

func distributionPointsForURL(t *testing.T, resourceURL string) []byte {
	t.Helper()
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(points *cryptobyte.Builder) {
		points.AddASN1(cryptobyte_asn1.SEQUENCE, func(point *cryptobyte.Builder) {
			point.AddASN1(
				cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(),
				func(name *cryptobyte.Builder) {
					name.AddASN1(
						cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(),
						func(fullName *cryptobyte.Builder) {
							fullName.AddASN1(
								cryptobyte_asn1.Tag(6).ContextSpecific(),
								func(uri *cryptobyte.Builder) { uri.AddBytes([]byte(resourceURL)) },
							)
						},
					)
				},
			)
		})
	})
	der, err := builder.Bytes()
	if err != nil {
		t.Fatalf("build DistributionPoints: %v", err)
	}
	return der
}
