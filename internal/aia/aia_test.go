package aia

import (
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
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

func TestParseIssuerResponseDER(t *testing.T) {
	der := testCertificateDER(t, "Test DER CA")

	certs, format, err := ParseIssuerResponse(der)
	if err != nil {
		t.Fatalf("ParseIssuerResponse returned error: %v", err)
	}
	if format != source.FormatDER {
		t.Fatalf("format = %q, want %q", format, source.FormatDER)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Test DER CA" {
		t.Fatalf("common name = %q, want %q", certs[0].Subject.CommonName, "Test DER CA")
	}
}

func TestParseIssuerResponsePEM(t *testing.T) {
	der := testCertificateDER(t, "Test PEM CA")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	certs, format, err := ParseIssuerResponse(pemData)
	if err != nil {
		t.Fatalf("ParseIssuerResponse returned error: %v", err)
	}
	if format != source.FormatPEM {
		t.Fatalf("format = %q, want %q", format, source.FormatPEM)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Test PEM CA" {
		t.Fatalf("common name = %q, want %q", certs[0].Subject.CommonName, "Test PEM CA")
	}
}

func TestParseIssuerResponsePKCS7(t *testing.T) {
	firstDER := testCertificateDER(t, "PKCS7 CA 1")
	secondDER := testCertificateDER(t, "PKCS7 CA 2")

	pkcs7DER, err := BuildCertsOnlyPKCS7(firstDER, secondDER)
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7: %v", err)
	}
	certs, format, err := ParseIssuerResponse(pkcs7DER)
	if err != nil {
		t.Fatalf("ParseIssuerResponse returned error: %v", err)
	}
	if format != source.FormatPKCS7 {
		t.Fatalf("format = %q, want %q", format, source.FormatPKCS7)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].Subject.CommonName != "PKCS7 CA 1" {
		t.Fatalf("first common name = %q, want %q", certs[0].Subject.CommonName, "PKCS7 CA 1")
	}
	if certs[1].Subject.CommonName != "PKCS7 CA 2" {
		t.Fatalf("second common name = %q, want %q", certs[1].Subject.CommonName, "PKCS7 CA 2")
	}
}

func TestParseIssuerResponseInvalid(t *testing.T) {
	_, _, err := ParseIssuerResponse([]byte("not a certificate"))
	if err == nil {
		t.Fatal("expected invalid response to fail")
	}
}

func TestFetchCAIssuer(t *testing.T) {
	der := testCertificateDER(t, "Fetched CA")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(der)
	}))
	defer server.Close()

	result, err := FetchCAIssuer(server.URL, time.Second)
	if err != nil {
		t.Fatalf("FetchCAIssuer returned error: %v", err)
	}
	if len(result.Certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(result.Certs))
	}
	if result.Certs[0].Subject.CommonName != "Fetched CA" {
		t.Fatalf("common name = %q, want %q", result.Certs[0].Subject.CommonName, "Fetched CA")
	}
	if result.Source.Type != source.Downloaded {
		t.Fatalf("source type = %q, want %q", result.Source.Type, source.Downloaded)
	}
	if result.Source.URL != server.URL {
		t.Fatalf("source URL = %q, want %q", result.Source.URL, server.URL)
	}
	if result.Source.Format != source.FormatDER {
		t.Fatalf("source format = %q, want %q", result.Source.Format, source.FormatDER)
	}
}

func TestFetchCAIssuerErrors(t *testing.T) {
	t.Run("empty url", func(t *testing.T) {
		_, err := FetchCAIssuer("", time.Second)
		if err == nil {
			t.Fatal("expected empty URL to fail")
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "missing", http.StatusNotFound)
		}))
		defer server.Close()

		_, err := FetchCAIssuer(server.URL, time.Second)
		if err == nil {
			t.Fatal("expected non-200 response to fail")
		}
	})

	t.Run("invalid body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not a certificate"))
		}))
		defer server.Close()

		_, err := FetchCAIssuer(server.URL, time.Second)
		if err == nil {
			t.Fatal("expected invalid body to fail")
		}
	})
}

func TestFetchCAIssuersCollectsResultsAndErrors(t *testing.T) {
	der := testCertificateDER(t, "Fetched CA")
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(der)
	}))
	defer goodServer.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer badServer.Close()

	results, errs := FetchCAIssuers([]string{goodServer.URL, badServer.URL}, time.Second)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
}

func TestSelectIssuer(t *testing.T) {
	subjectMatch := &zx509.Certificate{
		Subject: zpkix.Name{CommonName: "Subject Match CA"},
	}
	keyIDMatch := &zx509.Certificate{
		Subject:      zpkix.Name{CommonName: "Key ID Match CA"},
		SubjectKeyId: []byte{0x01, 0x02, 0x03},
	}
	fallback := &zx509.Certificate{
		Subject: zpkix.Name{CommonName: "Fallback CA"},
	}

	tests := []struct {
		name       string
		child      *zx509.Certificate
		candidates []*zx509.Certificate
		want       *zx509.Certificate
		matched    bool
	}{
		{
			name: "nil child",
		},
		{
			name:  "empty candidates",
			child: &zx509.Certificate{},
		},
		{
			name: "subject match",
			child: &zx509.Certificate{
				Issuer: zpkix.Name{CommonName: "Subject Match CA"},
			},
			candidates: []*zx509.Certificate{fallback, subjectMatch},
			want:       subjectMatch,
			matched:    true,
		},
		{
			name: "authority key identifier match",
			child: &zx509.Certificate{
				Issuer:         zpkix.Name{CommonName: "Unknown CA"},
				AuthorityKeyId: []byte{0x01, 0x02, 0x03},
			},
			candidates: []*zx509.Certificate{fallback, keyIDMatch},
			want:       keyIDMatch,
			matched:    true,
		},
		{
			name: "no match returns nil",
			child: &zx509.Certificate{
				Issuer: zpkix.Name{CommonName: "Unknown CA"},
			},
			candidates: []*zx509.Certificate{fallback, subjectMatch},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched := SelectIssuer(tt.child, tt.candidates)
			if got != tt.want {
				t.Fatalf("issuer = %v, want %v", got, tt.want)
			}
			if matched != tt.matched {
				t.Fatalf("matched = %v, want %v", matched, tt.matched)
			}
		})
	}
}

func TestToStdCert(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		cert, err := ToStdCert(nil)
		if err != nil {
			t.Fatalf("ToStdCert(nil) returned error: %v", err)
		}
		if cert != nil {
			t.Fatalf("ToStdCert(nil) = %v, want nil", cert)
		}
	})

	t.Run("valid", func(t *testing.T) {
		zcert, err := zx509.ParseCertificate(testCertificateDER(t, "ToStdCert CA"))
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}

		stdCert, err := ToStdCert(zcert)
		if err != nil {
			t.Fatalf("ToStdCert returned error: %v", err)
		}
		if stdCert.Subject.CommonName != "ToStdCert CA" {
			t.Fatalf("common name = %q, want %q", stdCert.Subject.CommonName, "ToStdCert CA")
		}
	})
}

func testCertificateDER(t *testing.T, commonName string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              stdx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return der
}

