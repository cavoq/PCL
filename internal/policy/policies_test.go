package policy

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func samplePolicy(name string) *Policy {
	return &Policy{
		Name: name,
	}
}

func writeTempPolicy(t *testing.T, dir, filename string, pol *Policy) string {
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

	pol, err := GetPolicy(path)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	if pol.Name != expected.Name {
		t.Errorf("expected Name %q, got %q", expected.Name, pol.Name)
	}
}

func TestGetPolicyChain_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	expected := samplePolicy("single-policy")
	path := writeTempPolicy(t, tmpDir, "policy.yaml", expected)

	chain, err := GetPolicyChain(path)
	if err != nil {
		t.Fatalf("GetPolicyChain failed: %v", err)
	}

	if len(chain.Policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(chain.Policies))
	}

	if chain.Policies[0].Name != expected.Name {
		t.Errorf("expected Name %q, got %q", expected.Name, chain.Policies[0].Name)
	}
}

func TestGetPolicyChain_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	order0 := 0
	order1 := 1
	pol1 := &Policy{Name: "leaf", CertOrder: &order0}
	pol2 := &Policy{Name: "root", CertOrder: &order1}

	writeTempPolicy(t, tmpDir, "leaf.yaml", pol1)
	writeTempPolicy(t, tmpDir, "root.yaml", pol2)

	chain, err := GetPolicyChain(tmpDir)
	if err != nil {
		t.Fatalf("GetPolicyChain failed: %v", err)
	}

	if len(chain.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(chain.Policies))
	}

	// Should be ordered by cert_order
	if chain.Policies[0].Name != "leaf" {
		t.Errorf("expected first policy to be 'leaf', got %q", chain.Policies[0].Name)
	}
	if chain.Policies[1].Name != "root" {
		t.Errorf("expected second policy to be 'root', got %q", chain.Policies[1].Name)
	}
}

func TestOrderPolicies(t *testing.T) {
	order0 := 0
	order1 := 1
	order2 := 2

	policies := []*Policy{
		{Name: "root", CertOrder: &order2},
		{Name: "leaf", CertOrder: &order0},
		{Name: "intermediate", CertOrder: &order1},
	}

	OrderPolicies(policies)

	expected := []string{"leaf", "intermediate", "root"}
	for i, pol := range policies {
		if pol.Name != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], pol.Name)
		}
	}
}

func TestOrderPolicies_DefaultOrder(t *testing.T) {
	order0 := 0

	policies := []*Policy{
		{Name: "no-order"},         // Should use DefaultCertOrder (1000)
		{Name: "leaf", CertOrder: &order0},
	}

	OrderPolicies(policies)

	if policies[0].Name != "leaf" {
		t.Errorf("expected leaf first, got %q", policies[0].Name)
	}
	if policies[1].Name != "no-order" {
		t.Errorf("expected no-order second, got %q", policies[1].Name)
	}
}

func TestGetCertOrder(t *testing.T) {
	order5 := 5

	tests := []struct {
		name     string
		input    *int
		expected int
	}{
		{"nil returns default", nil, DefaultCertOrder},
		{"value returns value", &order5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCertOrder(tt.input)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}
