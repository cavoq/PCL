package crl

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/loader"
	"github.com/cavoq/PCL/internal/source"
)

func TestParseCRL_PEM(t *testing.T) {
	crl, err := loader.Load(filepath.Join("testdata", "test.pem"), ParseCRL)
	if err != nil {
		t.Fatalf("failed to load PEM CRL: %v", err)
	}
	if crl == nil {
		t.Fatal("expected CRL, got nil")
	}
	if crl.Issuer.CommonName != "Test CA" {
		t.Errorf("expected issuer CN 'Test CA', got %q", crl.Issuer.CommonName)
	}
}

func TestParseCRL_DER(t *testing.T) {
	crl, err := loader.Load(filepath.Join("testdata", "test.crl"), ParseCRL)
	if err != nil {
		t.Fatalf("failed to load DER CRL: %v", err)
	}
	if crl == nil {
		t.Fatal("expected CRL, got nil")
	}
}

func TestParseCRL_Invalid(t *testing.T) {
	_, err := ParseCRL([]byte("not a CRL"))
	if err == nil {
		t.Fatal("expected error for invalid CRL data")
	}
}

func TestGetCRLFiles_SingleFile(t *testing.T) {
	files, err := GetCRLFiles(filepath.Join("testdata", "test.crl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestGetCRLFiles_Directory(t *testing.T) {
	files, err := GetCRLFiles("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) < 2 {
		t.Errorf("expected at least 2 CRL files, got %d", len(files))
	}
}

func TestGetCRLFiles_NotFound(t *testing.T) {
	_, err := GetCRLFiles("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetCRLs_SingleFile(t *testing.T) {
	crls, err := GetCRLs(filepath.Join("testdata", "test.crl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(crls) != 1 {
		t.Fatalf("expected 1 CRL, got %d", len(crls))
	}
	if crls[0].CRL == nil {
		t.Fatal("expected CRL, got nil")
	}
	if crls[0].Hash == "" {
		t.Error("expected non-empty hash")
	}
	if crls[0].FilePath == "" {
		t.Error("expected non-empty file path")
	}
	if crls[0].Source.Type != source.Local {
		t.Fatalf("expected local source, got %q", crls[0].Source.Type)
	}
	if crls[0].Format != FormatPEM {
		t.Fatalf("expected PEM format, got %q", crls[0].Format)
	}
}

func TestGetCRLs_Directory(t *testing.T) {
	crls, err := GetCRLs("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(crls) < 2 {
		t.Errorf("expected at least 2 CRLs, got %d", len(crls))
	}
}

func TestGetCRLs_WithRevokedCert(t *testing.T) {
	crls, err := GetCRLs(filepath.Join("testdata", "test_with_revoked.crl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(crls) != 1 {
		t.Fatalf("expected 1 CRL, got %d", len(crls))
	}
	if len(crls[0].CRL.RevokedCertificates) == 0 {
		t.Error("expected revoked certificates in CRL")
	}
}

func TestGetCRLs_NoValidCRLs(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.crl")
	if err := os.WriteFile(invalidFile, []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := GetCRLs(tmpDir)
	if err == nil {
		t.Fatal("expected error when no valid CRLs found")
	}
}

func TestFetchCRL_DER(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.crl"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatal("expected X509 CRL PEM fixture")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(block.Bytes)
	}))
	defer server.Close()

	result, err := FetchCRL(server.URL, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL, got nil")
	}
	if result.Format != FormatDER {
		t.Fatalf("expected DER format, got %q", result.Format)
	}
	if result.Source.Type != source.Downloaded {
		t.Fatalf("expected downloaded source, got %q", result.Source.Type)
	}
	if result.Source.URL != server.URL {
		t.Fatalf("expected URL %q, got %q", server.URL, result.Source.URL)
	}
	if result.FilePath != server.URL {
		t.Fatalf("expected file path %q, got %q", server.URL, result.FilePath)
	}
	if result.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestFetchCRL_PEM(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.pem"))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()

	result, err := FetchCRL(server.URL, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL, got nil")
	}
	if result.Format != FormatPEM {
		t.Fatalf("expected PEM format, got %q", result.Format)
	}
	if result.Source.Type != source.Downloaded {
		t.Fatalf("expected downloaded source, got %q", result.Source.Type)
	}
}
