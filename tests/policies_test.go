package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/RCV/internal/policy"
	"gopkg.in/yaml.v3"
)

func samplePolicy(name string) *policy.Policy {
	return &policy.Policy{
		Name: name,
	}
}

func writeTempPolicy(t *testing.T, dir, filename string, pol *policy.Policy) string {
	t.Helper()
	data, err := yaml.Marshal(pol)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}

	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write temp policy file: %v", err)
	}
	return path
}

func TestGetPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	expected := samplePolicy("test-policy")
	path := writeTempPolicy(t, tmpDir, "policy1.yaml", expected)

	pol, err := policy.GetPolicy(path)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	if pol.Name != expected.Name {
		t.Errorf("expected Name %q, got %q", expected.Name, pol.Name)
	}
}
