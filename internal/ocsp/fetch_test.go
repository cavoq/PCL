package ocsp

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
)

func TestFetchOCSP_NilCert(t *testing.T) {
	_, err := FetchOCSP(nil, &x509.Certificate{}, "http://example.com", 5, nil)
	if err == nil {
		t.Error("Expected error for nil cert")
	}
}

func TestFetchOCSPTimeout(t *testing.T) {
	issuer := testpki.Issue(t, "Issuer", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", issuer, testpki.Serial(2))
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	started := time.Now()
	_, err := FetchOCSP(
		leaf.Std,
		issuer.Std,
		server.URL,
		20*time.Millisecond,
		&NonceOptions{Disabled: true},
	)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FetchOCSP() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("FetchOCSP() returned after %v, want prompt deadline handling", elapsed)
	}
}

func TestFetchOCSPNetworkFailure(t *testing.T) {
	issuer := testpki.Issue(t, "Issuer", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", issuer, testpki.Serial(2))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = FetchOCSP(leaf.Std, issuer.Std, url, time.Second, &NonceOptions{Disabled: true})
	if err == nil || !strings.Contains(err.Error(), "OCSP request to ") {
		t.Fatalf("FetchOCSP() error = %v, want network failure", err)
	}
}

func TestFetchOCSPPreservesIssuerMismatchForAssessment(t *testing.T) {
	issuer := testpki.Issue(t, "Issuer", nil, testpki.CA())
	otherIssuer := testpki.Issue(t, "Other Issuer", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", issuer, testpki.Serial(2))
	issuerMismatchResponse, err := xocsp.CreateResponse(otherIssuer.Std, otherIssuer.Std, xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: leaf.Std.SerialNumber,
		ThisUpdate:   testpki.NotBefore,
		NextUpdate:   testpki.NotAfter,
	}, otherIssuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(issuerMismatchResponse)
	}))
	defer server.Close()

	info, err := FetchOCSP(
		leaf.Std,
		issuer.Std,
		server.URL,
		time.Second,
		&NonceOptions{Disabled: true},
	)
	if err != nil {
		t.Fatalf("FetchOCSP() error = %v", err)
	}
	assessment := AssessCertificate(
		leaf.Cert,
		[]*Info{info},
		[]*zx509.Certificate{issuer.Cert},
		testpki.NotBefore.Add(time.Hour),
	)
	if len(assessment.Evidence) != 1 || assessment.Evidence[0].IssuerMatched ||
		assessment.Status() != StatusNotApplicable {
		t.Fatalf("issuer-mismatched assessment = %#v", assessment)
	}
}

func TestFetchOCSP_NilIssuer(t *testing.T) {
	_, err := FetchOCSP(&x509.Certificate{}, nil, "http://example.com", 5, nil)
	if err == nil {
		t.Error("Expected error for nil issuer")
	}
}

func TestFetchOCSP_EmptyURL(t *testing.T) {
	_, err := FetchOCSP(&x509.Certificate{}, &x509.Certificate{}, "", 5, nil)
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

func TestFetchOCSP_Server(t *testing.T) {
	issuer := testpki.Issue(t, "Issuer", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", issuer, testpki.Serial(2))
	response, err := xocsp.CreateResponse(issuer.Std, issuer.Std, xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: leaf.Std.SerialNumber,
		ThisUpdate:   testpki.NotBefore,
		NextUpdate:   testpki.NotAfter,
	}, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{name: "good response", handler: func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write(response)
		}},
		{name: "error status", handler: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}, wantErr: "server returned status 503"},
		{name: "oversized response", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, maxOCSPResponseBytes+1))
		}, wantErr: "exceeds"},
		{name: "not an OCSP response", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("garbage"))
		}, wantErr: "failed to parse OCSP response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			info, err := FetchOCSP(leaf.Std, issuer.Std, server.URL, time.Second, &NonceOptions{Disabled: true})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.Response.Status != xocsp.Good || info.Source.Type != source.Downloaded || info.Source.URL != server.URL {
				t.Fatalf("info = status %d, source %+v", info.Response.Status, info.Source)
			}
		})
	}
}

func TestFetchForChain(t *testing.T) {
	var (
		mu       sync.Mutex
		requests = make(map[string]int)
		answers  = make(map[string][]byte)
	)
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request, err := xocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		serial := request.SerialNumber.String()
		mu.Lock()
		requests[serial]++
		answer := answers[serial]
		mu.Unlock()
		_, _ = w.Write(answer)
	}))
	defer responder.Close()
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer unavailable.Close()

	withOCSP := func(url string) testpki.Option {
		return testpki.Mutate(func(template *x509.Certificate) { template.OCSPServer = []string{url} })
	}
	// The root names a responder too; as the chain top it has no issuer in
	// the chain and must not be queried.
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1), withOCSP(responder.URL))
	intermediate := testpki.Issue(t, "Intermediate", root, testpki.CA(), testpki.Serial(2), withOCSP(responder.URL))
	quiet := testpki.Issue(t, "Quiet", intermediate, testpki.CA(), testpki.Serial(3))
	failing := testpki.Issue(t, "Failing", quiet, testpki.CA(), testpki.Serial(4), withOCSP(unavailable.URL))
	leaf := testpki.Issue(t, "Leaf", failing, testpki.Serial(5), withOCSP(responder.URL))
	for _, pair := range []struct{ subject, issuer *testpki.Certificate }{
		{leaf, failing}, {intermediate, root},
	} {
		answers[pair.subject.Std.SerialNumber.String()] = testpki.OCSPResponse(t, pair.issuer, pair.issuer, xocsp.Response{
			Status:       xocsp.Good,
			SerialNumber: pair.subject.Std.SerialNumber,
			ThisUpdate:   testpki.NotBefore,
			NextUpdate:   testpki.NotAfter,
		}).Raw
	}
	info := func(certificate *testpki.Certificate) *cert.Info { return &cert.Info{Cert: certificate.Cert} }
	chain := []*cert.Info{info(leaf), info(failing), info(quiet), info(intermediate), info(root)}

	results, errs := FetchForChain(chain, time.Second, &NonceOptions{Disabled: true})
	if len(results) != 2 || results[0].Response.SerialNumber.Int64() != 5 ||
		results[1].Response.SerialNumber.Int64() != 2 {
		t.Fatalf("results = %v, want responses for the leaf and the intermediate in chain order", results)
	}
	for _, result := range results {
		if result.Response.Status != xocsp.Good || result.Source.Type != source.Downloaded ||
			result.Source.URL != responder.URL {
			t.Fatalf("result = status %d, source %+v", result.Response.Status, result.Source)
		}
	}
	if len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "cert 1: ") ||
		!strings.Contains(errs[0].Error(), unavailable.URL) {
		t.Fatalf("errors = %v, want one for the failing responder of certificate 1", errs)
	}
	if requests["1"] != 0 || requests["3"] != 0 || requests["2"] != 1 || requests["5"] != 1 {
		t.Fatalf("requests per serial = %v, want one each for the leaf and the intermediate", requests)
	}

	t.Run("short and incomplete chains", func(t *testing.T) {
		for name, chain := range map[string][]*cert.Info{
			"empty":              nil,
			"single certificate": {info(leaf)},
			"certificate without a parsed certificate": {{}, info(failing)},
		} {
			if results, errs := FetchForChain(chain, time.Second, nil); len(results) != 0 || len(errs) != 0 {
				t.Fatalf("%s: results %v, errors %v; want none", name, results, errs)
			}
		}
		results, errs := FetchForChain([]*cert.Info{info(leaf), {}}, time.Second, nil)
		if len(results) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "issuer certificate is required") {
			t.Fatalf("missing issuer: results %v, errors %v", results, errs)
		}
	})
}
