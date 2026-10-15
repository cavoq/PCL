package testpki

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// SeedFiles returns the contents of the repository files matching patterns,
// which are relative to the repository root, for use as fuzz seeds. A file
// with PEM blocks contributes each block's DER instead of its text.
func SeedFiles(t testing.TB, patterns ...string) [][]byte {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository root")
	}
	root := filepath.Join(filepath.Dir(here), "..", "..")

	var seeds [][]byte
	for _, pattern := range patterns {
		files, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatalf("seed pattern %s: %v", pattern, err)
		}
		if len(files) == 0 {
			t.Fatalf("seed pattern %s matches no files", pattern)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			seeds = append(seeds, pemBlocksOr(data)...)
		}
	}
	return seeds
}

// pemBlocksOr returns the DER of every PEM block in data, or data itself
// when it holds none.
func pemBlocksOr(data []byte) [][]byte {
	var blocks [][]byte
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		blocks = append(blocks, block.Bytes)
	}
	if len(blocks) == 0 {
		return [][]byte{data}
	}
	return blocks
}
