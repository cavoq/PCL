package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
)

// lint runs the lint command like the CLI and returns every rule result.
func lint(t *testing.T, cfg linter.Config) ([]policy.Result, error) {
	t.Helper()
	cfg.OutputFmt, cfg.Verbosity, cfg.ShowMeta = output.FormatJSON, 2, false
	var out bytes.Buffer
	if err := linter.Run(cfg, &out); err != nil {
		return nil, err
	}
	var results []policy.Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("parse lint output: %v\n%s", err, out.String())
	}
	return results, nil
}

// writeTestFile writes data to name in dir and returns the path.
func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
