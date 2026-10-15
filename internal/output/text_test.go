package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

func TestVerdictLabel(t *testing.T) {
	tests := []struct {
		verdict  string
		expected string
	}{
		{rule.VerdictPass, "PASS"},
		{rule.VerdictFail, "FAIL"},
		{rule.VerdictSkip, "SKIP"},
		{"unknown", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			result := verdictLabel(tt.verdict)
			if result != tt.expected {
				t.Errorf("verdictLabel(%q) = %q, want %q", tt.verdict, result, tt.expected)
			}
		})
	}
}

func TestPaletteVerdict(t *testing.T) {
	tests := []struct {
		verdict       string
		expectedColor string
	}{
		{rule.VerdictPass, ansiGreen},
		{rule.VerdictFail, ansiRed},
		{rule.VerdictSkip, ansiCyan},
	}

	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			result := palette(true).verdict(tt.verdict)
			if !strings.Contains(result, tt.expectedColor) {
				t.Errorf("verdict(%q) should contain color code %q", tt.verdict, tt.expectedColor)
			}
			if !strings.Contains(result, ansiReset) {
				t.Error("colored verdict should contain reset code")
			}
		})
	}
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"", ""},
		{"info", "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := severityLabel(tt.severity)
			if result != tt.expected {
				t.Errorf("severityLabel(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestPaletteSeverity(t *testing.T) {
	result := palette(true).severity("warning")
	if !strings.Contains(result, ansiYellow) {
		t.Error("warning severity should be colored yellow")
	}

	result = palette(true).severity("error")
	if strings.Contains(result, ansiYellow) || strings.Contains(result, ansiRed) || strings.Contains(result, ansiGreen) {
		// Non-warning severities should not be colored
		t.Error("non-warning severity should not be colored")
	}
}

func TestWriteRulesTable_Empty(t *testing.T) {
	var buf bytes.Buffer

	err := writeRulesTable(&buf, palette(true), nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "(no rules to display)") {
		t.Error("empty results should show 'no rules to display'")
	}
}

func TestWriteRulesTable_EmptyWithCounts(t *testing.T) {
	var buf bytes.Buffer

	err := writeRulesTable(&buf, palette(true), nil, 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "(no rules to display with current verbosity)") {
		t.Error("empty results with counts should show verbosity message")
	}
}

func TestWriteRulesTable_WithResults(t *testing.T) {
	results := []rule.Result{
		{RuleID: "rule-1", Verdict: rule.VerdictPass},
		{RuleID: "rule-2", Verdict: rule.VerdictFail, Message: "failed check"},
	}

	var buf bytes.Buffer
	err := writeRulesTable(&buf, palette(true), results, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "rule-1") {
		t.Error("should contain rule-1")
	}
	if !strings.Contains(result, "rule-2") {
		t.Error("should contain rule-2")
	}
	if !strings.Contains(result, "failed check") {
		t.Error("should contain failure message")
	}
	if !strings.Contains(result, "VERDICT") {
		t.Error("should contain header")
	}
}

func TestWriteRulesTable_WithReference(t *testing.T) {
	results := []rule.Result{
		{RuleID: "rule-1", Verdict: rule.VerdictPass, Reference: "RFC 5280"},
	}

	var buf bytes.Buffer
	err := writeRulesTable(&buf, palette(true), results, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "RFC 5280") {
		t.Error("should contain reference")
	}
	if !strings.Contains(result, "REFERENCE") {
		t.Error("should contain REFERENCE header")
	}
}

func TestWriteRulesTable_WithWarnings(t *testing.T) {
	results := []rule.Result{
		{RuleID: "rule-1", Verdict: rule.VerdictFail, Severity: "warning"},
	}

	var buf bytes.Buffer
	err := writeRulesTable(&buf, palette(true), results, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "SEVERITY") {
		t.Error("should contain SEVERITY header when there are warnings")
	}
}

func TestTextFormatter_Format(t *testing.T) {
	formatter := NewTextFormatter(Options{ShowMeta: true})

	output := LintOutput{
		Meta: LintMeta{
			CheckedAt:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			TotalCerts:   2,
			TotalRules:   5,
			PassedRules:  3,
			FailedRules:  1,
			SkippedRules: 1,
		},
		Results: []policy.Result{
			{
				PolicyID: "test-policy",
				CertType: "leaf",
				CertPath: "/path/to/cert.pem",
				Verdict:  rule.VerdictFail,
				Results: []rule.Result{
					{RuleID: "r1", Verdict: rule.VerdictPass},
					{RuleID: "r2", Verdict: rule.VerdictFail},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(&buf, output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()

	// Check summary line
	if !strings.Contains(result, "[Summary]") {
		t.Error("should contain summary")
	}
	if !strings.Contains(result, "Certs: 2") {
		t.Error("should contain cert count")
	}

	// Check file line
	if !strings.Contains(result, "[File]") {
		t.Error("should contain file section")
	}
	if !strings.Contains(result, "test-policy") {
		t.Error("should contain policy ID")
	}
	if !strings.Contains(result, "/path/to/cert.pem") {
		t.Error("should contain cert path")
	}
}

func TestTextFormatter_EmptyCertPath(t *testing.T) {
	formatter := NewTextFormatter(Options{ShowMeta: false})

	output := LintOutput{
		Results: []policy.Result{
			{
				PolicyID: "test-policy",
				CertPath: "",
				Verdict:  rule.VerdictPass,
			},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(&buf, output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "File: -") {
		t.Error("empty cert path should display as '-'")
	}
}

func TestTextFormatter_MultipleResults(t *testing.T) {
	formatter := NewTextFormatter(Options{ShowMeta: false})

	output := LintOutput{
		Results: []policy.Result{
			{PolicyID: "policy1", Verdict: rule.VerdictPass},
			{PolicyID: "policy2", Verdict: rule.VerdictFail},
		},
	}

	var buf bytes.Buffer
	err := formatter.Format(&buf, output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "policy1") || !strings.Contains(result, "policy2") {
		t.Error("should contain both policies")
	}

	// Should have separator between results
	if strings.Count(result, "========") < 2 {
		t.Error("should have separators between multiple results")
	}
}

func TestPaletteOffWritesPlainText(t *testing.T) {
	plain := palette(false)
	if got := plain.verdict(rule.VerdictFail); got != "FAIL" {
		t.Errorf("verdict = %q, want FAIL", got)
	}
	if got := plain.verdictCell(rule.VerdictPass, rule.SeverityError, 6); got != "PASS  " {
		t.Errorf("verdictCell = %q, want padded PASS", got)
	}

	var out bytes.Buffer
	formatter := NewTextFormatter(Options{ShowMeta: true})
	err := formatter.Format(&out, LintOutput{Results: []policy.Result{{
		PolicyID: "p",
		Verdict:  rule.VerdictFail,
		Results:  []rule.Result{{RuleID: "r", Verdict: rule.VerdictFail, Severity: rule.SeverityWarning}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\033[") {
		t.Fatalf("output without Color contains ANSI codes:\n%q", out.String())
	}
}

// The summary counts every rule, including those the options hide.
func TestTextFormatterCountsHiddenRules(t *testing.T) {
	var out bytes.Buffer
	formatter := NewTextFormatter(Options{ShowFailed: true, ShowMeta: true})
	results := []policy.Result{{
		PolicyID: "p",
		Verdict:  rule.VerdictFail,
		Results: []rule.Result{
			{RuleID: "passed-rule", Verdict: rule.VerdictPass},
			{RuleID: "failed-rule", Verdict: rule.VerdictFail, Severity: rule.SeverityWarning},
			{RuleID: "skipped-rule", Verdict: rule.VerdictSkip},
		},
	}}
	if err := formatter.Format(&out, FromPolicyResults(results)); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"PASS: 1, FAIL: 1, SKIP: 1, WARN: 1", "failed-rule"} {
		if !strings.Contains(text, want) {
			t.Errorf("output does not contain %q:\n%s", want, text)
		}
	}
	for _, hidden := range []string{"passed-rule", "skipped-rule"} {
		if strings.Contains(text, hidden) {
			t.Errorf("output lists hidden rule %s:\n%s", hidden, text)
		}
	}
}
