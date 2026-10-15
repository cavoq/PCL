package linter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyTestsExampleSuites(t *testing.T) {
	var out bytes.Buffer
	summary, err := RunPolicyTests([]string{filepath.Join("..", "..", "tests", "policy-suites")}, &out)
	if err != nil {
		t.Fatalf("RunPolicyTests: %v\n%s", err, out.String())
	}
	if summary.Failed != 0 || summary.Passed < 6 {
		t.Fatalf("summary = %+v\n%s", summary, out.String())
	}
}

func writePolicySuite(t *testing.T, body string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "case.test.yaml")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(body, "$ROOT", root)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunPolicyTestsReportsFailedExpectations(t *testing.T) {
	suite := writePolicySuite(t, `
policy: $ROOT/tests/policies/ocsp-good.yaml
time: 2026-10-01
tests:
  - name: wrong expectations
    cert: $ROOT/tests/certs/ocsp-leaf.pem
    issuers: [$ROOT/tests/certs/ocsp-intermediate.pem, $ROOT/tests/certs/ocsp-root.pem]
    ocsp: $ROOT/tests/ocsps/revoked-leaf.ocsp
    expect:
      - input: leaf
        verdict: pass
        rules:
          ocsp-status-good: pass
          no-such-rule: fail
      - input: crl
        verdict: pass
  - name: missing error
    cert: $ROOT/tests/certs/ocsp-leaf.pem
    error: never happens
`)
	var out bytes.Buffer
	summary, err := RunPolicyTests([]string{suite}, &out)
	if err != nil {
		t.Fatalf("RunPolicyTests: %v", err)
	}
	if summary.Failed != 2 || summary.Passed != 0 {
		t.Fatalf("summary = %+v\n%s", summary, out.String())
	}
	for _, want := range []string{
		"leaf: policy integration-ocsp-good verdict fail, want pass",
		"leaf: rule ocsp-status-good fail, want pass",
		"leaf: rule no-such-rule was not evaluated",
		"crl: no policy evaluated this input",
		`expected an error containing "never happens"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestLoadPolicySuiteRejectsInvalidFiles(t *testing.T) {
	tests := map[string]string{
		"field expct not found":              "policy: p.yaml\ntests:\n  - name: typo\n    cert: a.pem\n    expct: []\n",
		"policy is required":                 "tests:\n  - name: t\n    cert: a.pem\n    error: x\n",
		"tests must not be empty":            "policy: p.yaml\ntests: []\n",
		"expect or error is required":        "policy: p.yaml\ntests:\n  - name: t\n    cert: a.pem\n",
		"verdict must be pass or fail":       "policy: p.yaml\ntests:\n  - name: t\n    expect: [{input: leaf, verdict: skip}]\n",
		"verdict must be pass, fail or skip": "policy: p.yaml\ntests:\n  - name: t\n    expect: [{input: leaf, rules: {r: ok}}]\n",
	}
	for want, body := range tests {
		path := filepath.Join(t.TempDir(), "suite.test.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPolicySuite(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("loadPolicySuite error = %v, want %q", err, want)
		}
	}
}

func TestLoadPolicySuiteCertificatePolicyInputs(t *testing.T) {
	path := writePolicySuite(t, `
policy: policy.yaml
tests:
  - name: policy processing inputs
    cert: leaf.pem
    certificatePolicyInputs:
      initialPolicySet: [1.2.3.4]
      initialExplicitPolicy: true
      initialPolicyMappingInhibit: true
      initialAnyPolicyInhibit: true
    error: fixture only
`)
	suite, err := loadPolicySuite(path)
	if err != nil {
		t.Fatal(err)
	}
	inputs := suite.Tests[0].CertificatePolicyInputs.operatorInputs()
	if !inputs.Configured || len(inputs.InitialPolicySet) != 1 ||
		!inputs.InitialExplicitPolicy || !inputs.InitialPolicyMappingInhibit ||
		!inputs.InitialAnyPolicyInhibit {
		t.Fatalf("certificate policy inputs = %#v", inputs)
	}
}

func TestParsePolicyTestTime(t *testing.T) {
	if parsed, err := parsePolicyTestTime("", "2026-10-01"); err != nil || parsed.Format("2006-01-02") != "2026-10-01" {
		t.Fatalf("suite time = %v, %v", parsed, err)
	}
	if parsed, err := parsePolicyTestTime("2027-01-02T03:04:05Z", "2026-10-01"); err != nil || parsed.Year() != 2027 {
		t.Fatalf("case time = %v, %v", parsed, err)
	}
	if parsed, err := parsePolicyTestTime("", ""); err != nil || !parsed.IsZero() {
		t.Fatalf("no time = %v, %v", parsed, err)
	}
	if _, err := parsePolicyTestTime("tomorrow", ""); err == nil {
		t.Fatal("invalid time accepted")
	}
}

func TestRunPolicyTestsWithoutSuites(t *testing.T) {
	if _, err := RunPolicyTests([]string{t.TempDir()}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for a directory without suites")
	}
}
