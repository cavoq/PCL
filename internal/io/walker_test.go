package io

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetFilesWithExtensions_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pem")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := GetFilesWithExtensions(testFile, ".pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
	if files[0] != testFile {
		t.Errorf("expected %s, got %s", testFile, files[0])
	}
}

func TestGetFilesWithExtensions_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	testFiles := []string{"test1.pem", "test2.crt", "test3.txt", "test4.pem"}
	for _, f := range testFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := GetFilesWithExtensions(tmpDir, ".pem", ".crt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d: %v", len(files), files)
	}
}

func TestGetFilesWithExtensions_NestedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "root.pem"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "nested.pem"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := GetFilesWithExtensions(tmpDir, ".pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files (including nested), got %d: %v", len(files), files)
	}
}

func TestGetFilesWithExtensions_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	files, err := GetFilesWithExtensions(tmpDir, ".pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestGetFilesWithExtensions_NoMatchingExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := GetFilesWithExtensions(tmpDir, ".pem", ".crt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestGetFilesWithExtensions_NonexistentPath(t *testing.T) {
	_, err := GetFilesWithExtensions("/nonexistent/path", ".pem")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetFilesWithExtensions_NoExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "test.pem"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := GetFilesWithExtensions(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files when no extensions specified, got %d", len(files))
	}
}

func TestGetFilesWithExtensions_SingleFileWrongExtension(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When given a single file path, it returns it regardless of extension
	files, err := GetFilesWithExtensions(testFile, ".pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file (single file path is always returned), got %d", len(files))
	}
}
