package cert

import (
	"path/filepath"
	"testing"
)

func TestGetCertificates_Chain(t *testing.T) {
	chain, err := GetCertificates("../../tests/certs")
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

func TestGetCertificates_SingleCert(t *testing.T) {
	chain, err := GetCertificates("../../tests/certs/leaf.pem")
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

func TestGetCertificate(t *testing.T) {
	cert, err := GetCertificate("../../tests/certs/leaf.pem")
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

	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d", len(files))
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
	chain, err := GetCertificates("../../tests/certs")
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
	chain, err := GetCertificates("../../tests/certs")
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
	chain, err := GetCertificates("../../tests/certs")
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
