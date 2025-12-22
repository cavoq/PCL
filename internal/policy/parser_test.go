package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_Valid(t *testing.T) {
	data := []byte(`
id: test-policy
rules:
  - id: check-version
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error
`)

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.ID != "test-policy" {
		t.Errorf("expected ID 'test-policy', got %q", p.ID)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
}

func TestParse_MultipleRules(t *testing.T) {
	data := []byte(`
id: test-policy
rules:
  - id: r1
    target: certificate.version
    operator: eq
    operands: [3]
  - id: r2
    target: certificate.subject.commonName
    operator: present
    severity: warning
`)

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(p.Rules))
	}
	if p.Rules[0].ID != "r1" {
		t.Errorf("expected first rule ID 'r1', got %q", p.Rules[0].ID)
	}
	if p.Rules[1].ID != "r2" {
		t.Errorf("expected second rule ID 'r2', got %q", p.Rules[1].ID)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	data := []byte(`invalid yaml [[[`)

	_, err := Parse(data)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	data := []byte(`
id: file-policy
rules:
  - id: r1
    target: certificate.version
    operator: eq
    operands: [3]
`)
	os.WriteFile(path, data, 0644)

	p, err := ParseFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.ID != "file-policy" {
		t.Errorf("expected ID 'file-policy', got %q", p.ID)
	}
}

func TestParseFile_NotFound(t *testing.T) {
	_, err := ParseFile("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseDir(t *testing.T) {
	dir := t.TempDir()

	p1 := []byte(`
id: policy1
rules:
  - id: r1
    target: certificate.version
    operator: eq
    operands: [3]
`)
	p2 := []byte(`
id: policy2
rules:
  - id: r2
    target: certificate.version
    operator: eq
    operands: [3]
`)

	os.WriteFile(filepath.Join(dir, "p1.yaml"), p1, 0644)
	os.WriteFile(filepath.Join(dir, "p2.yml"), p2, 0644)
	os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("not yaml"), 0644)

	policies, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestParseDir_SkipsSubdirs(t *testing.T) {
	dir := t.TempDir()

	p := []byte(`
id: policy1
rules:
  - id: r1
    target: certificate.version
    operator: eq
    operands: [3]
`)
	os.WriteFile(filepath.Join(dir, "p.yaml"), p, 0644)
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	policies, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestParseDir_NotFound(t *testing.T) {
	_, err := ParseDir("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

func TestParse_ListOperands(t *testing.T) {
	data := []byte(`
id: test-policy
rules:
  - id: algo-check
    target: certificate.signatureAlgorithm.algorithm
    operator: in
    operands:
      - SHA256-RSA
      - SHA384-RSA
    severity: error
`)

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}

	operands := p.Rules[0].Operands
	if len(operands) != 2 {
		t.Fatalf("expected 2 operands, got %d: %v", len(operands), operands)
	}

	if operands[0] != "SHA256-RSA" {
		t.Errorf("expected operand[0] to be 'SHA256-RSA', got %v (type %T)", operands[0], operands[0])
	}
}
