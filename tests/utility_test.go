package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/RCV/internal/utils"
)

func testCertDir(t *testing.T) string {
	dir := "BSI-TR-03116-TS/certs"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("test cert directory does not exist: %s", dir)
	}
	return dir
}

func TestCollectPaths_File(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testfile*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	paths, err := utils.CollectPaths(tmpFile.Name())
	if err != nil {
		t.Fatalf("CollectPaths failed for file: %v", err)
	}

	if len(paths) != 1 {
		t.Fatalf("expected 1 path for file, got %d", len(paths))
	}

	if paths[0] != tmpFile.Name() {
		t.Errorf("expected path %s, got %s", tmpFile.Name(), paths[0])
	}
}

func TestCollectPaths_Directory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	files := []string{"a.pem", "b.der", "c.txt"}
	for _, f := range files {
		fPath := filepath.Join(tmpDir, f)
		if _, err := os.Create(fPath); err != nil {
			t.Fatalf("failed to create temp file %s: %v", fPath, err)
		}
	}

	paths, err := utils.CollectPaths(tmpDir)
	if err != nil {
		t.Fatalf("CollectPaths failed for directory: %v", err)
	}

	if len(paths) != len(files) {
		t.Fatalf("expected %d files, got %d", len(files), len(paths))
	}

	found := make(map[string]bool)
	for _, p := range paths {
		found[filepath.Base(p)] = true
	}
	for _, f := range files {
		if !found[f] {
			t.Errorf("expected file %s not found in output", f)
		}
	}
}

func TestCollectPaths_NonExistent(t *testing.T) {
	_, err := utils.CollectPaths("/path/does/not/exist")
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
}

func TestGetCertFiles(t *testing.T) {
	dir := testCertDir(t)

	files, err := utils.GetCertFiles(dir)
	if err != nil {
		t.Fatalf("GetCertFiles failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("GetCertFiles returned 0 files, expected at least 1")
	}

	for _, f := range files {
		ext := filepath.Ext(f)
		if ext != ".pem" && ext != ".der" {
			t.Errorf("unexpected file extension %s in GetCertFiles output", ext)
		}
	}
}

func TestGetCertificate(t *testing.T) {
	dir := testCertDir(t)

	files, err := utils.GetCertFiles(dir)
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot find any test certificates: %v", err)
	}

	cert, err := utils.GetCertificate(files[0])
	if err != nil {
		t.Fatalf("GetCertificate failed on %s: %v", files[0], err)
	}

	if cert.Subject.CommonName == "" && len(cert.DNSNames) == 0 {
		t.Errorf("loaded certificate seems empty: %+v", cert.Subject)
	}
}

func TestGetCertificates(t *testing.T) {
	dir := testCertDir(t)

	certs, err := utils.GetCertificates(dir)
	if err != nil {
		t.Fatalf("GetCertificates failed: %v", err)
	}

	if len(certs) == 0 {
		t.Fatal("GetCertificates returned 0 certificates, expected at least 1")
	}
}
