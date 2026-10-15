package crl

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/testpki"
)

func parseCRLFile(t *testing.T, path string) (*x509.RevocationList, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ParseCRL(data)
}

func TestParseCRL_PEM(t *testing.T) {
	crl, err := parseCRLFile(t, filepath.Join("testdata", "test.pem"))
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
	crl, err := parseCRLFile(t, filepath.Join("testdata", "test.crl"))
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
	crls, err := GetCRLs(filepath.Join("testdata", "test.crl"), nil)
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
	if crls[0].Format != source.FormatPEM {
		t.Fatalf("expected PEM format, got %q", crls[0].Format)
	}
}

func TestGetCRLs_Directory(t *testing.T) {
	crls, err := GetCRLs("testdata", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(crls) < 2 {
		t.Errorf("expected at least 2 CRLs, got %d", len(crls))
	}
}

func TestGetCRLs_WithRevokedCert(t *testing.T) {
	crls, err := GetCRLs(filepath.Join("testdata", "test_with_revoked.crl"), nil)
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

	_, err := GetCRLs(tmpDir, nil)
	if err == nil {
		t.Fatal("expected error when no valid CRLs found")
	}
}

func TestFetchCRL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.crl"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatal("expected X509 CRL PEM fixture")
	}

	for _, tt := range []struct {
		body   []byte
		format source.Format
	}{
		{block.Bytes, source.FormatDER},
		{data, source.FormatPEM},
	} {
		t.Run(string(tt.format), func(t *testing.T) {
			url := testpki.Serve(t, tt.body)
			result, err := FetchCRL(url, time.Second)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.CRL == nil {
				t.Fatal("expected CRL, got nil")
			}
			if result.Format != tt.format {
				t.Fatalf("format = %q, want %q", result.Format, tt.format)
			}
			if result.Source.Type != source.Downloaded {
				t.Fatalf("expected downloaded source, got %q", result.Source.Type)
			}
			if result.Source.URL != url || result.FilePath != url {
				t.Fatalf("source URL = %q, file path = %q, want %q", result.Source.URL, result.FilePath, url)
			}
			if result.Hash == "" {
				t.Fatal("expected non-empty hash")
			}
		})
	}
}

func TestGetCRLs_ReportsSkippedFiles(t *testing.T) {
	dir := t.TempDir()
	valid, err := os.ReadFile(filepath.Join("testdata", "test.crl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "valid.crl"), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.crl"), []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	var diagnostics bytes.Buffer
	crls, err := GetCRLs(dir, &diagnostics)
	if err != nil || len(crls) != 1 {
		t.Fatalf("GetCRLs() = %d CRLs, %v; want the valid one", len(crls), err)
	}
	if !strings.Contains(diagnostics.String(), "Warning: skipped "+filepath.Join(dir, "broken.crl")) {
		t.Fatalf("diagnostics = %q, want a warning for broken.crl", diagnostics.String())
	}
}
