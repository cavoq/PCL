package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, subject string, isCA bool, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	parent := template
	parentKey := key
	if issuer != nil {
		parent = issuer
		parentKey = issuerKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

func writeCertPEM(t *testing.T, dir, filename string, cert *x509.Certificate) string {
	t.Helper()

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		t.Fatalf("failed to encode PEM: %v", err)
	}

	return path
}

func TestGetCertFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some test files
	os.WriteFile(filepath.Join(tmpDir, "cert1.pem"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "cert2.der"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "other.txt"), []byte("test"), 0644)

	files, err := GetCertFiles(tmpDir)
	if err != nil {
		t.Fatalf("GetCertFiles failed: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}

	for _, f := range files {
		ext := filepath.Ext(f)
		if ext != ".pem" && ext != ".der" {
			t.Errorf("unexpected file extension %s", ext)
		}
	}
}

func TestGetCertFiles_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cert.pem")
	os.WriteFile(path, []byte("test"), 0644)

	files, err := GetCertFiles(path)
	if err != nil {
		t.Fatalf("GetCertFiles failed: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestGetCertFiles_InvalidExtension(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cert.txt")
	os.WriteFile(path, []byte("test"), 0644)

	files, err := GetCertFiles(path)
	if err != nil {
		t.Fatalf("GetCertFiles failed: %v", err)
	}

	if len(files) != 0 {
		t.Errorf("expected 0 files for .txt extension, got %d", len(files))
	}
}

func TestGetCertificate_PEM(t *testing.T) {
	tmpDir := t.TempDir()
	testCert, _ := generateTestCert(t, "Test Cert", false, nil, nil)
	path := writeCertPEM(t, tmpDir, "test.pem", testCert)

	cert, err := GetCertificate(path)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != "Test Cert" {
		t.Errorf("expected CommonName 'Test Cert', got %q", cert.Subject.CommonName)
	}
}

func TestGetCertificate_DER(t *testing.T) {
	tmpDir := t.TempDir()
	testCert, _ := generateTestCert(t, "Test Cert DER", false, nil, nil)

	path := filepath.Join(tmpDir, "test.der")
	if err := os.WriteFile(path, testCert.Raw, 0644); err != nil {
		t.Fatalf("failed to write DER file: %v", err)
	}

	cert, err := GetCertificate(path)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != "Test Cert DER" {
		t.Errorf("expected CommonName 'Test Cert DER', got %q", cert.Subject.CommonName)
	}
}

func TestGetCertificate_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.pem")
	os.WriteFile(path, []byte("not a certificate"), 0644)

	_, err := GetCertificate(path)
	if err == nil {
		t.Error("expected error for invalid certificate")
	}
}

func TestGetCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a chain: root -> intermediate -> leaf
	root, rootKey := generateTestCert(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := generateTestCert(t, "Intermediate CA", true, root, rootKey)
	leaf, _ := generateTestCert(t, "Leaf Cert", false, intermediate, intermediateKey)

	writeCertPEM(t, tmpDir, "root.pem", root)
	writeCertPEM(t, tmpDir, "intermediate.pem", intermediate)
	writeCertPEM(t, tmpDir, "leaf.pem", leaf)

	certs, err := GetCertificates(tmpDir)
	if err != nil {
		t.Fatalf("GetCertificates failed: %v", err)
	}

	if len(certs) != 3 {
		t.Errorf("expected 3 certificates, got %d", len(certs))
	}

	// Verify CertInfo fields are populated
	for _, c := range certs {
		if c.FilePath == "" {
			t.Error("expected FilePath to be set")
		}
		if c.Hash == "" {
			t.Error("expected Hash to be set")
		}
		if c.Cert == nil {
			t.Error("expected Cert to be set")
		}
	}
}

func TestGetCertificates_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := GetCertificates(tmpDir)
	if err == nil {
		t.Error("expected error when no certificates found")
	}
}

func TestFindLongestChain(t *testing.T) {
	// Create a chain: root -> intermediate -> leaf
	root, rootKey := generateTestCert(t, "Root CA", true, nil, nil)
	intermediate, intermediateKey := generateTestCert(t, "Intermediate CA", true, root, rootKey)
	leaf, _ := generateTestCert(t, "Leaf Cert", false, intermediate, intermediateKey)

	certs := []*CertInfo{
		{Cert: leaf, FilePath: "leaf.pem", Hash: "leafhash"},
		{Cert: root, FilePath: "root.pem", Hash: "roothash"},
		{Cert: intermediate, FilePath: "intermediate.pem", Hash: "intermediatehash"},
	}

	chain, err := FindLongestChain(certs)
	if err != nil {
		t.Fatalf("FindLongestChain failed: %v", err)
	}

	if len(chain) != 3 {
		t.Errorf("expected chain length 3, got %d", len(chain))
	}

	// Chain should start with leaf
	if chain[0].Cert.Subject.CommonName != "Leaf Cert" {
		t.Errorf("expected chain to start with leaf, got %q", chain[0].Cert.Subject.CommonName)
	}
}

func TestFindLongestChain_Empty(t *testing.T) {
	_, err := FindLongestChain([]*CertInfo{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestFindLongestChain_SingleCert(t *testing.T) {
	cert, _ := generateTestCert(t, "Single", false, nil, nil)
	certs := []*CertInfo{
		{Cert: cert, FilePath: "single.pem", Hash: "singlehash"},
	}

	chain, err := FindLongestChain(certs)
	if err != nil {
		t.Fatalf("FindLongestChain failed: %v", err)
	}

	if len(chain) != 1 {
		t.Errorf("expected chain length 1, got %d", len(chain))
	}
}
