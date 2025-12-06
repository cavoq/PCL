package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/utils"
)

func testCertDir(t *testing.T) string {
	dir := "BSI-TR-03116-TS/certs"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("test cert directory does not exist: %s", dir)
	}
	return dir
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
