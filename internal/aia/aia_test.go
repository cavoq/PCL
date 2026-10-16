package aia

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
)

func TestBuildCertsOnlyPKCS7_rejectsEmptyDER(t *testing.T) {
	if _, err := BuildCertsOnlyPKCS7([]byte{}); err == nil {
		t.Fatal("expected error for empty certificate DER")
	}
}

func TestParseIssuerResponse(t *testing.T) {
	first := testCertificateDER(t, "CA 1")
	second := testCertificateDER(t, "CA 2")
	pkcs7DER, err := BuildCertsOnlyPKCS7(first, second)
	if err != nil {
		t.Fatalf("BuildCertsOnlyPKCS7: %v", err)
	}

	tests := []struct {
		name   string
		body   []byte
		format source.Format
		names  []string
	}{
		{"DER", first, source.FormatDER, []string{"CA 1"}},
		{"PEM", testpki.PEM("CERTIFICATE", first), source.FormatPEM, []string{"CA 1"}},
		{"PKCS7", pkcs7DER, source.FormatPKCS7, []string{"CA 1", "CA 2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, format, err := ParseIssuerResponse(tt.body)
			if err != nil {
				t.Fatalf("ParseIssuerResponse returned error: %v", err)
			}
			if format != tt.format {
				t.Fatalf("format = %q, want %q", format, tt.format)
			}
			if len(certs) != len(tt.names) {
				t.Fatalf("got %d certs, want %d", len(certs), len(tt.names))
			}
			for index, name := range tt.names {
				if certs[index].Subject.CommonName != name {
					t.Fatalf("common name %d = %q, want %q", index, certs[index].Subject.CommonName, name)
				}
			}
		})
	}
}

func TestParseIssuerResponseInvalid(t *testing.T) {
	_, _, err := ParseIssuerResponse([]byte("not a certificate"))
	if err == nil {
		t.Fatal("expected invalid response to fail")
	}
}

func TestFetchCAIssuer(t *testing.T) {
	url := testpki.Serve(t, testCertificateDER(t, "Fetched CA"))

	result, err := FetchCAIssuer(url, time.Second)
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
	if result.Source.URL != url {
		t.Fatalf("source URL = %q, want %q", result.Source.URL, url)
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
		_, err := FetchCAIssuer(testpki.Serve(t, []byte("not a certificate")), time.Second)
		if err == nil {
			t.Fatal("expected invalid body to fail")
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		oversized := make([]byte, maxCAIssuersResponseBytes+1)
		_, err := FetchCAIssuer(testpki.Serve(t, oversized), time.Second)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v, want the size limit", err)
		}
	})
}

func TestFetchCAIssuersCollectsResultsAndErrors(t *testing.T) {
	goodURL := testpki.Serve(t, testCertificateDER(t, "Fetched CA"))
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer badServer.Close()

	results, errs := FetchCAIssuers([]string{goodURL, badServer.URL}, time.Second)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
}

func TestFetchCAIssuersSkipsLDAPWhenHTTPPresent(t *testing.T) {
	ldapURL := "ldap://directory.example/cn=CA?cACertificate?base"
	goodURL := testpki.Serve(t, testCertificateDER(t, "Fetched CA"))

	results, errs := FetchCAIssuers([]string{ldapURL, goodURL}, time.Second)
	if len(errs) != 0 {
		t.Fatalf("errors = %v, want none", errs)
	}
	if len(results) != 1 || results[0].Source.URL != goodURL {
		t.Fatalf("results = %v, want only %s", results, goodURL)
	}
}

func TestFetchCAIssuersWarnsOnceWithoutHTTP(t *testing.T) {
	urls := []string{
		"ldap://directory.example/cn=CA?cACertificate?base",
		"LDAP://directory.example/cn=CA?cACertificate;binary?base",
	}

	results, errs := FetchCAIssuers(urls, time.Second)
	if len(results) != 0 {
		t.Fatalf("got %d results, want none", len(results))
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly one", errs)
	}
	want := "only ldap:// CA Issuers URLs (" + strings.Join(urls, ", ") + "); LDAP retrieval is not supported"
	if errs[0].Error() != want {
		t.Fatalf("error = %q, want %q", errs[0], want)
	}
}

func TestSupportedCAIssuersURLs(t *testing.T) {
	supported, err := SupportedCAIssuersURLs([]string{"ldap://a.example/", "HTTPS://b.example/ca.crt", "http://c.example/ca.crt"})
	if err != nil {
		t.Fatalf("SupportedCAIssuersURLs: %v", err)
	}
	if !slices.Equal(supported, []string{"HTTPS://b.example/ca.crt", "http://c.example/ca.crt"}) {
		t.Fatalf("supported = %v", supported)
	}

	if supported, err := SupportedCAIssuersURLs(nil); err != nil || supported != nil {
		t.Fatalf("SupportedCAIssuersURLs(nil) = %v, %v; want nil, nil", supported, err)
	}

	_, err = SupportedCAIssuersURLs([]string{"ftp://a.example/ca.crt", "ldap://b.example/", "%zz"})
	want := "only ftp://, ldap:// CA Issuers URLs (ftp://a.example/ca.crt, ldap://b.example/, %zz); FTP and LDAP retrieval is not supported"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
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

func testCertificateDER(t *testing.T, commonName string) []byte {
	t.Helper()
	return testpki.Issue(t, commonName, nil, testpki.CA()).DER
}

// TestParseIssuerResponseAcceptsCompatibilityCertificates checks that CA
// Issuers responses parse certificates like local files do, including
// inherited DSA parameters and CRL distribution points zcrypto rejects.
func TestParseIssuerResponseAcceptsCompatibilityCertificates(t *testing.T) {
	var ders [][]byte
	for _, file := range []string{"DSAParametersInheritedCACert.crt", "ValiddistributionPointTest4EE.crt"} {
		der, err := os.ReadFile(filepath.Join("..", "..", "tests", "pkits", "certs", file))
		if err != nil {
			t.Fatal(err)
		}
		ders = append(ders, der)
	}
	bundle, err := BuildCertsOnlyPKCS7(ders...)
	if err != nil {
		t.Fatal(err)
	}

	bodies := map[string][]byte{"PKCS7": bundle, "PEM PKCS7": testpki.PEM("PKCS7", bundle)}
	for index, der := range ders {
		bodies["DER "+strconv.Itoa(index)] = der
		bodies["PEM "+strconv.Itoa(index)] = testpki.PEM("CERTIFICATE", der)
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			certs, _, err := ParseIssuerResponse(body)
			if err != nil {
				t.Fatalf("ParseIssuerResponse: %v", err)
			}
			for _, certificate := range certs {
				if !slices.ContainsFunc(ders, func(der []byte) bool { return bytes.Equal(der, certificate.Raw) }) {
					t.Fatal("parsed certificate does not preserve the served DER")
				}
			}
		})
	}
}
