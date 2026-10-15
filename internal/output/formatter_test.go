package output

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

func TestGetFormatter(t *testing.T) {
	tests := map[string]Formatter{
		"text":    &TextFormatter{},
		"json":    &JSONFormatter{},
		"yaml":    &YAMLFormatter{},
		"unknown": &TextFormatter{},
		"":        &TextFormatter{},
	}
	for format, want := range tests {
		if got := GetFormatter(format, Options{}); reflect.TypeOf(got) != reflect.TypeOf(want) {
			t.Errorf("GetFormatter(%q) = %T, want %T", format, got, want)
		}
	}
}

func TestStructuredFormatters(t *testing.T) {
	for _, tt := range []struct {
		name      string
		formatter func(Options) Formatter
		unmarshal func([]byte, any) error
	}{
		{"JSON", func(opts Options) Formatter { return NewJSONFormatter(opts) }, json.Unmarshal},
		{"YAML", func(opts Options) Formatter { return NewYAMLFormatter(opts) }, yaml.Unmarshal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			format := func(showMeta bool, into any) {
				t.Helper()
				var buf bytes.Buffer
				opts := Options{ShowMeta: showMeta, ShowPassed: true, ShowFailed: true}
				if err := tt.formatter(opts).Format(&buf, createTestOutput()); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if err := tt.unmarshal(buf.Bytes(), into); err != nil {
					t.Fatalf("failed to parse output: %v", err)
				}
			}

			var withMeta LintOutput
			format(true, &withMeta)
			if withMeta.Meta.TotalCerts != 1 {
				t.Errorf("expected meta.total_certs=1, got %d", withMeta.Meta.TotalCerts)
			}

			var results []policy.Result
			format(false, &results)
			if len(results) != 1 {
				t.Errorf("expected 1 result, got %d", len(results))
			}
			if got := results[0].Results[0].Details; got != "actual: 1; expected: 1" {
				t.Errorf("details = %q", got)
			}
		})
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
					{
						RuleID:   "r1",
						Verdict:  rule.VerdictPass,
						Severity: "error",
						Details:  "actual: 1; expected: 1",
					},
					{RuleID: "r2", Verdict: rule.VerdictFail, Severity: "error"},
				},
			},
		},
	}
}

func TestCheckFormat(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON, FormatYAML} {
		if err := CheckFormat(format); err != nil {
			t.Errorf("CheckFormat(%q) = %v", format, err)
		}
	}
	for _, format := range []string{"", "xml", "JSON"} {
		if err := CheckFormat(format); err == nil {
			t.Errorf("CheckFormat(%q) accepted an unknown format", format)
		}
	}
}
