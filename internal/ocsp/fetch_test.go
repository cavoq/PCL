package ocsp

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
