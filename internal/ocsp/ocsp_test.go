package ocsp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOCSP_Invalid(t *testing.T) {
	_, err := ParseOCSP([]byte("not an ocsp response"))
	if err == nil {
		t.Fatal("expected error for invalid OCSP data")
	}
}

func TestParseOCSP_InvalidPEM(t *testing.T) {
	pemData := `-----BEGIN OCSP RESPONSE-----
bm90IHZhbGlkIGRhdGE=
-----END OCSP RESPONSE-----`

	_, err := ParseOCSP([]byte(pemData))
	if err == nil {
		t.Fatal("expected error for invalid PEM OCSP data")
	}
}

func TestGetOCSPFiles_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ocsp")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := GetOCSPFiles(testFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestGetOCSPFiles_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files with different extensions
	testFiles := []struct {
		name    string
		matched bool
	}{
		{"test1.ocsp", true},
		{"test2.der", true},
		{"test3.pem", true},
		{"test4.txt", false},
		{"test5.crl", false},
	}

	for _, tf := range testFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, tf.name), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := GetOCSPFiles(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCount := 0
	for _, tf := range testFiles {
		if tf.matched {
			expectedCount++
		}
	}

	if len(files) != expectedCount {
		t.Errorf("expected %d files, got %d: %v", expectedCount, len(files), files)
	}
}

func TestGetOCSPFiles_NotFound(t *testing.T) {
	_, err := GetOCSPFiles("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetOCSPs_NoValidOCSPs(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.ocsp")
	if err := os.WriteFile(invalidFile, []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := GetOCSPs(tmpDir)
	if err == nil {
		t.Fatal("expected error when no valid OCSP responses found")
	}
}

func TestGetOCSPs_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-OCSP file to ensure directory isn't empty but has no OCSP files
	if err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	resps, err := GetOCSPs(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resps) != 0 {
		t.Errorf("expected 0 responses for empty directory, got %d", len(resps))
	}
}

func TestGetOCSPs_NotFound(t *testing.T) {
	_, err := GetOCSPs("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetOCSPs_SkipsInvalidFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid OCSP file and a non-OCSP file
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.ocsp"), []byte("not valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "another.ocsp"), []byte("also not valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Should return error since all OCSP files are invalid
	_, err := GetOCSPs(tmpDir)
	if err == nil {
		t.Fatal("expected error when all OCSP files are invalid")
	}
}
