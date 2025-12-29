package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

func TestGetFormatter_Text(t *testing.T) {
	formatter := GetFormatter("text", Options{})
	if _, ok := formatter.(*TextFormatter); !ok {
		t.Errorf("expected TextFormatter, got %T", formatter)
	}
}

func TestGetFormatter_JSON(t *testing.T) {
	formatter := GetFormatter("json", Options{})
	if _, ok := formatter.(*JSONFormatter); !ok {
		t.Errorf("expected JSONFormatter, got %T", formatter)
	}
}

func TestGetFormatter_YAML(t *testing.T) {
	formatter := GetFormatter("yaml", Options{})
	if _, ok := formatter.(*YAMLFormatter); !ok {
		t.Errorf("expected YAMLFormatter, got %T", formatter)
	}
}

func TestGetFormatter_Unknown(t *testing.T) {
	formatter := GetFormatter("unknown", Options{})
	if _, ok := formatter.(*TextFormatter); !ok {
		t.Errorf("unknown format should default to TextFormatter, got %T", formatter)
	}
}

func TestGetFormatter_Empty(t *testing.T) {
	formatter := GetFormatter("", Options{})
	if _, ok := formatter.(*TextFormatter); !ok {
		t.Errorf("empty format should default to TextFormatter, got %T", formatter)
	}
}

func TestJSONFormatter_WithMeta(t *testing.T) {
	formatter := NewJSONFormatter(Options{ShowMeta: true})
	output := createTestOutput()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result LintOutput
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result.Meta.TotalCerts != 1 {
		t.Errorf("expected meta.total_certs=1, got %d", result.Meta.TotalCerts)
	}
}

func TestJSONFormatter_WithoutMeta(t *testing.T) {
	formatter := NewJSONFormatter(Options{ShowMeta: false})
	output := createTestOutput()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var results []policy.Result
	if err := json.Unmarshal(buf.Bytes(), &results); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestYAMLFormatter_WithMeta(t *testing.T) {
	formatter := NewYAMLFormatter(Options{ShowMeta: true})
	output := createTestOutput()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result LintOutput
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse YAML output: %v", err)
	}

	if result.Meta.TotalCerts != 1 {
		t.Errorf("expected meta.total_certs=1, got %d", result.Meta.TotalCerts)
	}
}

func TestYAMLFormatter_WithoutMeta(t *testing.T) {
	formatter := NewYAMLFormatter(Options{ShowMeta: false})
	output := createTestOutput()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var results []policy.Result
	if err := yaml.Unmarshal(buf.Bytes(), &results); err != nil {
		t.Fatalf("failed to parse YAML output: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestTextFormatter_WithMeta(t *testing.T) {
	formatter := NewTextFormatter(Options{ShowMeta: true})
	output := createTestOutput()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "[Summary]") {
		t.Error("expected output to contain [Summary] when ShowMeta is true")
	}
}

func TestTextFormatter_WithoutMeta(t *testing.T) {
	formatter := NewTextFormatter(Options{ShowMeta: false})
	output := createTestOutput()

	var buf bytes.Buffer
	if err := formatter.Format(&buf, output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if strings.Contains(result, "[Summary]") {
		t.Error("expected output not to contain [Summary] when ShowMeta is false")
	}
}

func createTestOutput() LintOutput {
	return LintOutput{
		Meta: LintMeta{
			CheckedAt:    time.Now(),
			TotalCerts:   1,
			TotalRules:   2,
			PassedRules:  1,
			FailedRules:  1,
			SkippedRules: 0,
		},
		Results: []policy.Result{
			{
				PolicyID: "test-policy",
				CertType: "leaf",
				CertPath: "/test/cert.pem",
				Verdict:  "fail",
				Results: []rule.Result{
					{RuleID: "r1", Verdict: rule.VerdictPass, Severity: "error"},
					{RuleID: "r2", Verdict: rule.VerdictFail, Severity: "error"},
				},
			},
		},
	}
}
