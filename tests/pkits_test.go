package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

// NIST PKITS 1.0.1 runs through the lint entry point. tests/pkits/manifest.json
// is generated from the PKITS description by tests/scripts/pkits-manifest.py.

const pkitsDir = "pkits"

// pkitsValidationTime lies inside the 2010-2030 validity of the PKITS data.
var pkitsValidationTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

type pkitsManifest struct {
	Tests []pkitsTest `json:"tests"`
}

type pkitsTest struct {
	ID      string     `json:"id"`
	Title   string     `json:"title"`
	EE      string     `json:"ee"`
	Issuers []string   `json:"issuers"`
	CRLs    []string   `json:"crls"`
	Runs    []pkitsRun `json:"runs"`
}

type pkitsRun struct {
	ExplicitPolicy       bool     `json:"explicitPolicy"`
	InitialPolicySet     []string `json:"initialPolicySet"`
	PolicyMappingInhibit bool     `json:"policyMappingInhibit"`
	AnyPolicyInhibit     bool     `json:"anyPolicyInhibit"`
	Expected             string   `json:"expected"`
}

// pkitsKnownGap documents a run whose PCL outcome differs from PKITS.
type pkitsKnownGap struct {
	Run    string `yaml:"run"`
	Reason string `yaml:"reason"`
}

func loadPKITS(t *testing.T) (pkitsManifest, map[string]string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pkitsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read PKITS manifest: %v", err)
	}
	var manifest pkitsManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse PKITS manifest: %v", err)
	}

	gaps := map[string]string{}
	data, err = os.ReadFile(filepath.Join(pkitsDir, "known-gaps.yaml"))
	if err != nil {
		t.Fatalf("read PKITS known gaps: %v", err)
	}
	var listed []pkitsKnownGap
	if err := yaml.Unmarshal(data, &listed); err != nil {
		t.Fatalf("parse PKITS known gaps: %v", err)
	}
	for _, gap := range listed {
		if gap.Reason == "" {
			t.Fatalf("known gap %s has no reason", gap.Run)
		}
		gaps[gap.Run] = gap.Reason
	}
	return manifest, gaps
}

func TestPKITS(t *testing.T) {
	manifest, gaps := loadPKITS(t)
	if len(manifest.Tests) != 224 {
		t.Fatalf("PKITS manifest has %d tests, want 224", len(manifest.Tests))
	}

	seenGaps := map[string]bool{}
	var conforming, gapped, unsupported int
	for _, test := range manifest.Tests {
		for index, run := range test.Runs {
			name := fmt.Sprintf("%s#%d", test.ID, index+1)
			if run.PolicyMappingInhibit || run.AnyPolicyInhibit {
				unsupported++
				continue // PCL has no initial-policy-mapping-inhibit or initial-any-policy-inhibit input
			}
			got, failures := runPKITS(t, test, run)
			reason, known := gaps[name]
			seenGaps[name] = known
			switch {
			case got == run.Expected && known:
				t.Errorf("%s %s: now %s as PKITS expects; remove it from known-gaps.yaml", name, test.Title, got)
			case got == run.Expected:
				conforming++
			case known:
				gapped++
				_ = reason
			default:
				t.Errorf("%s %s: %s, PKITS expects %s; failed rules: %v", name, test.Title, got, run.Expected, failures)
			}
		}
	}
	for name := range gaps {
		if _, ok := seenGaps[name]; !ok {
			t.Errorf("known gap %s does not name a PKITS run", name)
		}
	}
	t.Logf("PKITS: %d runs conform, %d known gaps, %d unsupported", conforming, gapped, unsupported)
}

// runPKITS lints one PKITS path and reports "valid" when no error rule fails
// for any certificate, together with the failed rules.
func runPKITS(t *testing.T, test pkitsTest, run pkitsRun) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	crlDir := filepath.Join(dir, "crls")
	if err := os.Mkdir(crlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, crlFile := range test.CRLs {
		data, err := os.ReadFile(filepath.Join(pkitsDir, crlFile))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(crlDir, filepath.Base(crlFile)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	policies := []string{
		filepath.Join(pkitsDir, "path-policy.yaml"),
		writePKITSPolicyRule(t, dir, pkitsAcceptablePolicies(run)),
	}

	issuers := make([]string, 0, len(test.Issuers))
	for _, issuer := range test.Issuers {
		issuers = append(issuers, filepath.Join(pkitsDir, issuer))
	}
	cfg := linter.Config{
		PolicyPaths:    policies,
		CertPath:       filepath.Join(pkitsDir, test.EE),
		IssuerPaths:    issuers,
		OutputFmt:      "json",
		ValidationTime: pkitsValidationTime,
	}
	if len(test.CRLs) > 0 {
		cfg.CRLPath = crlDir
	}

	var out bytes.Buffer
	if err := linter.Run(cfg, &out); err != nil {
		return "invalid", []string{"error: " + err.Error()}
	}
	var results []policy.Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("%s: parse lint output: %v\n%s", test.ID, err, out.String())
	}
	var failures []string
	for _, result := range results {
		for _, ruleResult := range result.Results {
			if ruleResult.Verdict != rule.VerdictFail || ruleResult.Severity != rule.SeverityError {
				continue
			}
			// RFC 5280 policy processing is defined for the whole path. A
			// prefix ending in a self-issued certificate may fail where the
			// path succeeds (6.1.3 (d)(2) allows anyPolicy only when i < n).
			if ruleResult.RuleID == pkitsPolicyRuleID && result.CertPath != cfg.CertPath {
				continue
			}
			failures = append(failures, result.CertType+":"+ruleResult.RuleID)
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		return "invalid", failures
	}
	return "valid", nil
}

// pkitsAcceptablePolicies returns the operands of certificatePolicyValid for
// a run: its initial-policy-set, anyPolicy when only initial-explicit-policy
// is set, and none for the RFC 5280 default inputs.
func pkitsAcceptablePolicies(run pkitsRun) []string {
	switch {
	case len(run.InitialPolicySet) > 0:
		return run.InitialPolicySet
	case run.ExplicitPolicy:
		return []string{"2.5.29.32.0"}
	default:
		return nil
	}
}

const pkitsPolicyRuleID = "certificate-policy-valid"

// writePKITSPolicyRule writes the policy processing rule for a run. Some
// PKITS paths end in a CA certificate, so the rule applies to every role but
// the trust anchor; runPKITS only counts its verdict for the end entity.
func writePKITSPolicyRule(t *testing.T, dir string, acceptable []string) string {
	t.Helper()
	quoted := make([]string, len(acceptable))
	for index, oid := range acceptable {
		quoted[index] = `"` + oid + `"`
	}
	path := filepath.Join(dir, "policy-processing.yaml")
	content := `id: pkits-policy-processing
appliesTo: [cert]
rules:
  - id: ` + pkitsPolicyRuleID + `
    reference: RFC5280 6.1
    target: certificate
    operator: certificatePolicyValid
    operands: [` + strings.Join(quoted, ", ") + `]
    certType: [leaf, intermediate, ocspSigning]
    severity: error
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
