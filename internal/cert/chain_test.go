package cert

import (
	"path/filepath"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/loader"
)

func TestLoadCertificates_Chain(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain) != 3 {
		t.Fatalf("expected 3 certs in chain, got %d", len(chain))
	}

	if chain[0].Type != "leaf" {
		t.Errorf("expected first cert to be leaf, got %s", chain[0].Type)
	}

	if chain[1].Type != "intermediate" {
		t.Errorf("expected second cert to be intermediate, got %s", chain[1].Type)
	}

	if chain[2].Type != "root" {
		t.Errorf("expected third cert to be root, got %s", chain[2].Type)
	}
}

func TestLoadCertificates_SingleCert(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(chain))
	}

	if chain[0].Type != "leaf" {
		t.Errorf("expected cert type leaf, got %s", chain[0].Type)
	}
}

func TestParseCertificate(t *testing.T) {
	cert, err := loader.Load("../../tests/certs/leaf.pem", ParseCertificate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cert.Subject.CommonName != "leaf.example.test" {
		t.Errorf("expected CN 'leaf.example.test', got %s", cert.Subject.CommonName)
	}
}

func TestGetCertFiles_Directory(t *testing.T) {
	files, err := GetCertFiles("../../tests/certs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Minimum 4 original files, plus generated test certificates
	if len(files) < 4 {
		t.Errorf("expected at least 4 files, got %d", len(files))
	}
}

func TestGetCertFiles_SingleFile(t *testing.T) {
	files, err := GetCertFiles("../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestBuildChain_Positions(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chain {
		if c.Position != i {
			t.Errorf("cert %d: expected position %d, got %d", i, i, c.Position)
		}
	}
}

func TestBuildChain_Hashes(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chain {
		if c.Hash == "" {
			t.Errorf("cert %d: hash should not be empty", i)
		}
		if len(c.Hash) != 64 {
			t.Errorf("cert %d: expected 64 char hash, got %d", i, len(c.Hash))
		}
	}
}

func TestBuildChain_FilePaths(t *testing.T) {
	certs, err := LoadCertificates("../../tests/certs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chain, err := BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, c := range chain {
		if c.FilePath == "" {
			t.Errorf("cert %d: file path should not be empty", i)
		}
		ext := filepath.Ext(c.FilePath)
		if ext != ".pem" {
			t.Errorf("cert %d: expected .pem extension, got %s", i, ext)
		}
	}
}

func TestGetCertType_ClassifiesIndependentOfPosition(t *testing.T) {
	root := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Root"},
		Issuer:                pkix.Name{CommonName: "Root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if got := GetCertType(root, 0, 3); got != "root" {
		t.Fatalf("expected root independent of position, got %q", got)
	}

	intermediate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Intermediate"},
		Issuer:                pkix.Name{CommonName: "Root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if got := GetCertType(intermediate, 0, 1); got != "intermediate" {
		t.Fatalf("expected intermediate independent of position, got %q", got)
	}

	ocspSigner := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "OCSP Signer"},
		Issuer:      pkix.Name{CommonName: "Intermediate"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOcspSigning},
	}
	if got := GetCertType(ocspSigner, 2, 3); got != "ocspSigning" {
		t.Fatalf("expected ocspSigning independent of position, got %q", got)
	}

	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Leaf"},
		Issuer:  pkix.Name{CommonName: "Intermediate"},
	}
	if got := GetCertType(leaf, 2, 3); got != "leaf" {
		t.Fatalf("expected leaf independent of position, got %q", got)
	}
}
