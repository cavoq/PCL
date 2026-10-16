package linter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/operator"
)

func TestBuiltinPoliciesParse(t *testing.T) {
	builtins, err := BuiltinPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(builtins) != 6 {
		t.Fatalf("%d built-in policies, want 6", len(builtins))
	}
	for _, builtin := range builtins {
		policies, err := loadPolicies([]string{BuiltinPolicyPrefix + builtin.ID}, operator.DefaultRegistry())
		if err != nil || len(policies) != 1 || policies[0].ID != builtin.ID {
			t.Errorf("load %s = %v, %v", builtin.ID, policies, err)
		}
	}
}

func TestLoadPoliciesResolvesBuiltinNames(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"rfc5280", "RFC5280", "RFC5280.yaml", "builtin:rfc5280", "builtin:RFC5280.yaml"} {
		policies, err := loadPolicies([]string{name}, operator.DefaultRegistry())
		if err != nil || len(policies) != 1 || policies[0].ID != "rfc5280" {
			t.Errorf("loadPolicies(%q) = %v, %v", name, policies, err)
		}
	}

	if _, err := loadPolicies([]string{"builtin:no-such-pack"}, operator.DefaultRegistry()); err == nil ||
		!strings.Contains(err.Error(), `unknown built-in policy "no-such-pack"`) {
		t.Errorf("unknown built-in error = %v", err)
	}
	if _, err := loadPolicies([]string{"no-such-pack"}, operator.DefaultRegistry()); err == nil ||
		!strings.Contains(err.Error(), "built-in policies: cabf-tls-br, local-profile, rfc4055") {
		t.Errorf("missing policy error = %v", err)
	}

	// A file of the same name takes precedence over the bare id.
	local := "id: local-rfc5280\nversion: \"1\"\nrules:\n  - id: r\n    target: certificate\n    operator: present\n    severity: error\n"
	if err := os.WriteFile("rfc5280", []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	policies, err := loadPolicies([]string{"rfc5280"}, operator.DefaultRegistry())
	if err != nil || len(policies) != 1 || policies[0].ID != "local-rfc5280" {
		t.Errorf("local file did not take precedence: %v, %v", policies, err)
	}
}

func TestPolicySuiteReferencesBuiltinPolicy(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	suite := filepath.Join(t.TempDir(), "builtin.test.yaml")
	body := `policy: rfc5280
time: 2026-10-01
tests:
  - name: leaf against the built-in RFC 5280 pack
    cert: ` + filepath.Join(root, "tests", "certs", "leaf.pem") + `
    issuers: [` + filepath.Join(root, "tests", "certs", "intermediate.pem") + `]
    expect:
      - input: leaf
        policy: rfc5280
        rules:
          leaf-not-ca: pass
`
	if err := os.WriteFile(suite, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	summary, err := RunPolicyTests([]string{suite}, &out)
	if err != nil || summary.Failed != 0 || summary.Passed != 1 {
		t.Fatalf("summary = %+v, %v\n%s", summary, err, out.String())
	}
}
