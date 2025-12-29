package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Success(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Load(testFile, func(data []byte) (string, error) {
		return string(data), nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/file", func(data []byte) (string, error) {
		return string(data), nil
	})
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_ParseError(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(testFile, func(data []byte) (string, error) {
		return "", fmt.Errorf("parse error")
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadAll_Success(t *testing.T) {
	tmpDir := t.TempDir()

	files := []string{"a.txt", "b.txt"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	results, err := LoadAll(
		tmpDir,
		[]string{".txt"},
		func(data []byte) (string, error) {
			return string(data), nil
		},
		func(s string) []byte {
			return []byte(s)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Hash == "" {
			t.Error("expected non-empty hash")
		}
		if r.FilePath == "" {
			t.Error("expected non-empty file path")
		}
	}
}

func TestLoadAll_SkipsInvalidFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid and invalid files
	if err := os.WriteFile(filepath.Join(tmpDir, "valid.txt"), []byte("valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.txt"), []byte("invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := LoadAll(
		tmpDir,
		[]string{".txt"},
		func(data []byte) (string, error) {
			if string(data) == "invalid" {
				return "", fmt.Errorf("invalid content")
			}
			return string(data), nil
		},
		func(s string) []byte {
			return []byte(s)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result (skipping invalid), got %d", len(results))
	}
}

func TestLoadAll_AllInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.txt"), []byte("invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadAll(
		tmpDir,
		[]string{".txt"},
		func(data []byte) (string, error) {
			return "", fmt.Errorf("parse error")
		},
		func(s string) []byte {
			return []byte(s)
		},
	)
	if err == nil {
		t.Fatal("expected error when all files are invalid")
	}
}

func TestLoadAll_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	results, err := LoadAll(
		tmpDir,
		[]string{".txt"},
		func(data []byte) (string, error) {
			return "", nil
		},
		func(s string) []byte {
			return []byte(s)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}
