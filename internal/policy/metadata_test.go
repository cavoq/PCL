package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestMetadataDoesNotChangeEvaluation(t *testing.T) {
	const rules = `id: example
rules:
  - {id: version, target: certificate.version, operator: eq, operands: [3], severity: error}
`
	plain, err := ParseWithRegistry([]byte(rules), operator.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	described, err := ParseWithRegistry([]byte(rules+`metadata:
  title: Example profile
  standard: RFC 5280
  edition: "2008"
  source: https://example.invalid/never-fetched
  description: Documentation only
  inputs: [trustAnchors, ocsp]
`), operator.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	want := &Metadata{
		Title: "Example profile", Standard: "RFC 5280", Edition: "2008",
		Source: "https://example.invalid/never-fetched", Description: "Documentation only",
		Inputs: []string{"trustAnchors", "ocsp"},
	}
	if !reflect.DeepEqual(described.Metadata, want) {
		t.Fatalf("metadata = %#v, want %#v", described.Metadata, want)
	}
	if !AppliesToInput(described, InputCert) || AppliesToInput(described, InputOCSP) {
		t.Fatal("metadata.inputs changed input selection inferred from rule targets")
	}
	// Deliberately omit the evidence listed in metadata. It must not become a
	// requirement, skip the rule, or alter its verdict.
	for _, version := range []int{2, 3} {
		root := node.New("certificate", nil)
		root.Children["version"] = node.New("version", version)
		a := Evaluate(plain, root, operator.DefaultRegistry(), nil)
		b := Evaluate(described, root, operator.DefaultRegistry(), nil)
		if a.Verdict != b.Verdict || !reflect.DeepEqual(a.Results, b.Results) {
			t.Fatalf("metadata changed evaluation: plain=%+v described=%+v", a, b)
		}
	}
}

func TestIncludesKeepOnlyParentMetadata(t *testing.T) {
	dir := t.TempDir()
	child := []byte(`id: child
metadata: {title: Child, inputs: [ocsp]}
rules:
  - {id: version, target: certificate.version, operator: eq, operands: [3], severity: error}
`)
	if err := os.WriteFile(filepath.Join(dir, "child.yaml"), child, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, metadata := range []string{"", "metadata: {title: Parent, inputs: [certificate]}\n"} {
		file := filepath.Join(dir, "parent.yaml")
		if err := os.WriteFile(file, []byte("id: parent\nincludes: [child.yaml]\n"+metadata), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := ParseFileWithRegistry(file, operator.DefaultRegistry())
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Rules) != 1 || p.Rules[0].ID != "version" {
			t.Fatalf("included rules = %+v", p.Rules)
		}
		if metadata == "" {
			if p.Metadata != nil {
				t.Fatalf("inherited child metadata: %+v", p.Metadata)
			}
		} else if !reflect.DeepEqual(p.Metadata, &Metadata{Title: "Parent", Inputs: []string{"certificate"}}) {
			t.Fatalf("parent metadata replaced: %+v", p.Metadata)
		}
	}
}
