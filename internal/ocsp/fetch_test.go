package ocsp

import (
	"crypto/x509"
	"testing"
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
