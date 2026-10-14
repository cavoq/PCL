package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

// lintCase is one tests/cases scenario. Paths are relative to tests/.
type lintCase struct {
	Name    string   `yaml:"name"`
	Policy  string   `yaml:"policy"`
	Rules   []string `yaml:"rules"`   // evaluate only these rules of Policy
	Fixture string   `yaml:"fixture"` // generated inputs, see fixtures_test.go
	Certs   string   `yaml:"certs"`
	Issuers []string `yaml:"issuers"`
	CRL     string   `yaml:"crl"`
	OCSP    string   `yaml:"ocsp"`
	Purpose string   `yaml:"purpose"`
	Time    string   `yaml:"time"` // RFC 3339 evaluation time
	// Error expects linting to fail with an error containing this text.
	Error string `yaml:"error"`
	// Output renders the lint again as text or yaml, which must contain
	// every Contains entry.
	Output   string   `yaml:"output"`
	Contains []string `yaml:"contains"`
	// Expected holds the rule verdict counts per evaluated input type
	// (leaf, intermediate, root, crl, ...) and optionally the policy verdict.
	Expected map[string]caseCounts `yaml:"expected"`
}

type caseCounts struct {
	Pass    int    `yaml:"pass"`
	Fail    int    `yaml:"fail"`
	Skip    int    `yaml:"skip"`
	Verdict string `yaml:"verdict"`
}

func TestCases(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("cases", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no cases found: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		var tc lintCase
		if err := decoder.Decode(&tc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		t.Run(tc.Name, func(t *testing.T) { runLintCase(t, tc) })
	}
}

func runLintCase(t *testing.T, tc lintCase) {
	if tc.Fixture != "" {
		tc = materializeCaseFixture(t, tc)
	}
	cfg := linter.Config{
		PolicyPaths:        []string{casePolicy(t, tc)},
		CertPath:           casePath(tc.Certs),
		CRLPath:            casePath(tc.CRL),
		OCSPPath:           casePath(tc.OCSP),
		ApplicationPurpose: tc.Purpose,
	}
	for _, issuer := range tc.Issuers {
		cfg.IssuerPaths = append(cfg.IssuerPaths, casePath(issuer))
	}
	if tc.Time != "" {
		evaluationTime, err := time.Parse(time.RFC3339, tc.Time)
		if err != nil {
			t.Fatalf("time: %v", err)
		}
		cfg.ValidationTime = evaluationTime
	}

	results, err := lint(t, cfg)
	if tc.Error != "" {
		if err == nil || !strings.Contains(err.Error(), tc.Error) {
			t.Fatalf("error = %v, want one containing %q", err, tc.Error)
		}
		return
	}
	if err != nil {
		t.Fatalf("lint: %v", err)
	}

	if len(results) != len(tc.Expected) {
		t.Errorf("%d inputs evaluated, want %d", len(results), len(tc.Expected))
	}
	for _, result := range results {
		want, ok := tc.Expected[result.CertType]
		if !ok {
			t.Errorf("unexpected input %s", result.CertType)
			continue
		}
		got := countVerdicts(result.Results)
		if want.Verdict != "" {
			got.Verdict = result.Verdict
		}
		if got != want {
			t.Errorf("%s: %+v, want %+v (failed rules: %v)", result.CertType, got, want, failedRuleIDs(result.Results))
		}
	}

	if tc.Output != "" {
		cfg.OutputFmt, cfg.ShowMeta = tc.Output, true
		var rendered bytes.Buffer
		if err := linter.Run(cfg, &rendered); err != nil {
			t.Fatalf("lint as %s: %v", tc.Output, err)
		}
		for _, want := range tc.Contains {
			if !strings.Contains(rendered.String(), want) {
				t.Errorf("%s output does not contain %q:\n%s", tc.Output, want, rendered.String())
			}
		}
	}
}

// casePath resolves a case path relative to tests/; fixtures use absolute
// paths.
func casePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(path)
}

// casePolicy returns the case's policy file, reduced to tc.Rules when set.
func casePolicy(t *testing.T, tc lintCase) string {
	t.Helper()
	path := casePath(tc.Policy)
	if len(tc.Rules) == 0 {
		return path
	}
	parsed, err := policy.ParseFileWithRegistry(path, operator.DefaultRegistry())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	var selected []rule.Rule
	for _, id := range tc.Rules {
		found := false
		for _, candidate := range parsed.Rules {
			if candidate.ID == id {
				selected, found = append(selected, candidate), true
			}
		}
		if !found {
			t.Fatalf("policy %s has no rule %q", parsed.ID, id)
		}
	}
	parsed.Rules, parsed.Includes = selected, nil
	data, err := yaml.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestFile(t, t.TempDir(), "policy.yaml", data)
}

func countVerdicts(results []rule.Result) caseCounts {
	var counts caseCounts
	for _, result := range results {
		switch result.Verdict {
		case rule.VerdictPass:
			counts.Pass++
		case rule.VerdictFail:
			counts.Fail++
		case rule.VerdictSkip:
			counts.Skip++
		}
	}
	return counts
}

func failedRuleIDs(results []rule.Result) []string {
	var identifiers []string
	for _, result := range results {
		if result.Verdict == rule.VerdictFail {
			identifiers = append(identifiers, result.RuleID)
		}
	}
	return identifiers
}
