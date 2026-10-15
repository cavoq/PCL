package ocsp

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	xocsp "golang.org/x/crypto/ocsp"

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
