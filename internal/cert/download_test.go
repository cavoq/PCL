package cert

import (
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/source"
)

func TestDownloadCertificatesWritesFiles(t *testing.T) {
	origFetcher := tlsChainFetcher
	tlsChainFetcher = func(_ string, _ string, _ time.Duration) ([]*tls.Certificate, error) {
		return []*tls.Certificate{
			{Certificate: [][]byte{[]byte("cert-one")}},
			{Certificate: [][]byte{[]byte("cert-two")}},
		}, nil
	}
	defer func() { tlsChainFetcher = origFetcher }()

	dir := t.TempDir()
	outDir, cleanup, err := DownloadCertificates([]string{"https://example.test"}, 5*time.Second, dir)
	if cleanup != nil {
		t.Fatalf("expected no cleanup when save dir provided")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outDir != dir {
		t.Fatalf("expected output dir %q, got %q", dir, outDir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("unexpected read dir error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 cert files, got %d", len(entries))
	}

	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatalf("expected PEM data in output file")
	}
}

func TestDownloadCertificatesTempDirCleanup(t *testing.T) {
	origFetcher := tlsChainFetcher
	tlsChainFetcher = func(_ string, _ string, _ time.Duration) ([]*tls.Certificate, error) {
		return []*tls.Certificate{
			{Certificate: [][]byte{[]byte("cert-one")}},
		}, nil
	}
	defer func() { tlsChainFetcher = origFetcher }()

	outDir, cleanup, err := DownloadCertificates([]string{"https://example.test"}, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanup == nil {
		t.Fatalf("expected cleanup for temp dir")
	}
	cleanup()
	if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected temp dir to be removed")
	}
}

func TestDownloadCertificatesRejectsHTTP(t *testing.T) {
	_, _, err := DownloadCertificates([]string{"http://example.test"}, 5*time.Second, "")
	if err == nil {
		t.Fatalf("expected error for http scheme")
	}
}

func TestDownloadAndLoadCertificatesPreservesSource(t *testing.T) {
	pemData, err := os.ReadFile("../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("expected certificate PEM fixture")
	}

	origFetcher := tlsChainFetcher
	tlsChainFetcher = func(_ string, _ string, _ time.Duration) ([]*tls.Certificate, error) {
		return []*tls.Certificate{{Certificate: [][]byte{block.Bytes}}}, nil
	}
	defer func() { tlsChainFetcher = origFetcher }()

	certs, cleanup, err := DownloadAndLoadCertificates([]string{"https://example.test"}, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected cleanup")
	}
	defer cleanup()

	if len(certs) != 1 {
		t.Fatalf("expected one certificate, got %d", len(certs))
	}
	if certs[0].Source.Type != source.Downloaded {
		t.Fatalf("expected downloaded source, got %+v", certs[0].Source)
	}
	if certs[0].Source.URL != "https://example.test" {
		t.Fatalf("expected source URL, got %q", certs[0].Source.URL)
	}
}
