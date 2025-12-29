package cert

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
