package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/output"
)

func TestLinterRunCases(t *testing.T) {
	caseFiles, err := filepath.Glob(filepath.Join("linter-cases", "*.yaml"))
	if err != nil {
		t.Fatalf("unexpected glob error: %v", err)
	}
	if len(caseFiles) == 0 {
		t.Fatalf("no linter cases found")
	}

	for _, caseFile := range caseFiles {
		tc, err := loadLinterCase(caseFile)
		if err != nil {
			t.Fatalf("failed to load case %s: %v", caseFile, err)
		}
		t.Run(tc.Name, func(t *testing.T) {
			runLinterCase(t, filepath.Dir(caseFile), tc)
		})
	}
}

type linterCase struct {
	Name          string         `yaml:"name"`
	Policy        string         `yaml:"policy"`
	Certs         string         `yaml:"certs,omitempty"`
	Issuers       []string       `yaml:"issuers,omitempty"`
	CRL           string         `yaml:"crl,omitempty"`
	OCSP          string         `yaml:"ocsp,omitempty"`
	Output        string         `yaml:"output,omitempty"`
	Verbosity     int            `yaml:"verbosity,omitempty"`
	ShowMeta      bool           `yaml:"show_meta,omitempty"`
	WantError     bool           `yaml:"want_error,omitempty"`
	ErrorContains string         `yaml:"error_contains,omitempty"`
	Contains      []string       `yaml:"contains,omitempty"`
	Expected      linterExpected `yaml:"expected,omitempty"`
}

type linterExpected struct {
	TotalCerts int                    `yaml:"total_certs"`
	TotalRules int                    `yaml:"total_rules"`
	Pass       int                    `yaml:"pass"`
	Fail       int                    `yaml:"fail"`
	Skip       int                    `yaml:"skip"`
	Results    []linterExpectedResult `yaml:"results"`
}

type linterExpectedResult struct {
	CertType string `yaml:"cert_type"`
	Policy   string `yaml:"policy"`
	Verdict  string `yaml:"verdict"`
	Rules    int    `yaml:"rules"`
}

func loadLinterCase(path string) (linterCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return linterCase{}, err
	}
	var tc linterCase
	if err := yaml.Unmarshal(data, &tc); err != nil {
		return linterCase{}, err
	}
	if tc.Name == "" {
		tc.Name = filepath.Base(path)
	}
	return tc, nil
}

func runLinterCase(t *testing.T, caseDir string, tc linterCase) {
	t.Helper()

	testsDir := filepath.Dir(caseDir)
	cfg := linter.Config{
		PolicyPaths: []string{filepath.Join(testsDir, tc.Policy)},
		OutputFmt:   tc.Output,
		Verbosity:   tc.Verbosity,
		ShowMeta:    tc.ShowMeta,
	}
	if tc.Certs != "" {
		cfg.CertPath = filepath.Join(testsDir, tc.Certs)
	}
	for _, issuer := range tc.Issuers {
		cfg.IssuerPaths = append(cfg.IssuerPaths, filepath.Join(testsDir, issuer))
	}
	if tc.CRL != "" {
		cfg.CRLPath = filepath.Join(testsDir, tc.CRL)
	}
	if tc.OCSP != "" {
		cfg.OCSPPath = filepath.Join(testsDir, tc.OCSP)
	}

	var buf bytes.Buffer
	err := linter.Run(cfg, &buf)
	if tc.WantError {
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if tc.ErrorContains != "" && !strings.Contains(err.Error(), tc.ErrorContains) {
			t.Fatalf("error = %q, want substring %q", err.Error(), tc.ErrorContains)
		}
		return
	}
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, want := range tc.Contains {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("output missing %q\n%s", want, buf.String())
		}
	}

	if tc.Output == "json" {
		assertLinterJSONOutput(t, buf.Bytes(), tc.Expected)
	}
}

func assertLinterJSONOutput(t *testing.T, data []byte, want linterExpected) {
	t.Helper()

	var got output.LintOutput
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("failed to decode JSON output: %v\n%s", err, string(data))
	}

	if got.Meta.TotalCerts != want.TotalCerts {
		t.Fatalf("TotalCerts = %d, want %d", got.Meta.TotalCerts, want.TotalCerts)
	}
	if got.Meta.TotalRules != want.TotalRules {
		t.Fatalf("TotalRules = %d, want %d", got.Meta.TotalRules, want.TotalRules)
	}
	if got.Meta.PassedRules != want.Pass {
		t.Fatalf("PassedRules = %d, want %d", got.Meta.PassedRules, want.Pass)
	}
	if got.Meta.FailedRules != want.Fail {
		t.Fatalf("FailedRules = %d, want %d", got.Meta.FailedRules, want.Fail)
	}
	if got.Meta.SkippedRules != want.Skip {
		t.Fatalf("SkippedRules = %d, want %d", got.Meta.SkippedRules, want.Skip)
	}
	if len(got.Results) != len(want.Results) {
		t.Fatalf("got %d results, want %d", len(got.Results), len(want.Results))
	}

	expectedByType := make(map[string]linterExpectedResult, len(want.Results))
	for _, expected := range want.Results {
		expectedByType[expected.CertType] = expected
	}

	for _, result := range got.Results {
		expected, ok := expectedByType[result.CertType]
		if !ok {
			t.Fatalf("unexpected result for cert type %q", result.CertType)
		}
		if result.PolicyID != expected.Policy {
			t.Fatalf("cert %s PolicyID = %q, want %q", result.CertType, result.PolicyID, expected.Policy)
		}
		if result.Verdict != expected.Verdict {
			t.Fatalf("cert %s Verdict = %q, want %q", result.CertType, result.Verdict, expected.Verdict)
		}
		if len(result.Results) != expected.Rules {
			t.Fatalf("cert %s has %d rules, want %d", result.CertType, len(result.Results), expected.Rules)
		}
	}
}
