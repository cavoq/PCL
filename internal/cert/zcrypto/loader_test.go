package zcrypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/cert/zcrypto"
)

func loadTestCert(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test cert %s: %v", name, err)
	}

	return data
}

func TestLoader_LoadValidPEM(t *testing.T) {
	loader := zcrypto.NewLoader()

	data := loadTestCert(t, "leaf.pem")

	cert, err := loader.Load(data)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cert == nil {
		t.Fatal("expected certificate, got nil")
	}
}

func TestLoader_InvalidPEM(t *testing.T) {
	loader := zcrypto.NewLoader()

	_, err := loader.Load([]byte("this is not a certificate"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestLoader_EmptyInput(t *testing.T) {
	loader := zcrypto.NewLoader()

	_, err := loader.Load(nil)
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}
