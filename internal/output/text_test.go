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

func TestVerdictLabelColored(t *testing.T) {
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
			result := verdictLabelColored(tt.verdict)
			if !strings.Contains(result, tt.expectedColor) {
				t.Errorf("verdictLabelColored(%q) should contain color code %q", tt.verdict, tt.expectedColor)
			}
			if !strings.Contains(result, ansiReset) {
				t.Error("colored verdict should contain reset code")
			}
		})
	}
}

func TestVerdictLabelColoredPadded(t *testing.T) {
	result := verdictLabelColoredPadded(rule.VerdictPass, 10)

	// Remove ANSI codes to check padding
	stripped := strings.ReplaceAll(result, ansiGreen, "")
	stripped = strings.ReplaceAll(stripped, ansiReset, "")

	if len(stripped) != 10 {
		t.Errorf("expected padded length 10, got %d: %q", len(stripped), stripped)
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

func TestSeverityLabelColored(t *testing.T) {
	result := severityLabelColored("warning")
	if !strings.Contains(result, ansiYellow) {
		t.Error("warning severity should be colored yellow")
	}

	result = severityLabelColored("error")
	if strings.Contains(result, ansiYellow) || strings.Contains(result, ansiRed) || strings.Contains(result, ansiGreen) {
		// Non-warning severities should not be colored
		t.Error("non-warning severity should not be colored")
	}
}

func TestColorize(t *testing.T) {
	result := colorize("test", ansiRed)
	expected := ansiRed + "test" + ansiReset
	if result != expected {
		t.Errorf("colorize result = %q, want %q", result, expected)
	}
}

func TestCountResults(t *testing.T) {
	results := []rule.Result{
		{Verdict: rule.VerdictPass},
		{Verdict: rule.VerdictPass},
		{Verdict: rule.VerdictFail, Severity: "error"},
		{Verdict: rule.VerdictFail, Severity: "warning"},
		{Verdict: rule.VerdictSkip},
	}

	passed, failed, skipped, warned := countResults(results)

	if passed != 2 {
		t.Errorf("expected 2 passed, got %d", passed)
	}
	if failed != 2 {
		t.Errorf("expected 2 failed, got %d", failed)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", skipped)
	}
	if warned != 1 {
		t.Errorf("expected 1 warned, got %d", warned)
	}
}

func TestCountWarnings(t *testing.T) {
	results := []policy.Result{
		{
			Counts: policy.Counts{Warned: 2},
		},
		{
			Results: []rule.Result{
				{Verdict: rule.VerdictFail, Severity: "warning"},
				{Verdict: rule.VerdictFail, Severity: "warning"},
				{Verdict: rule.VerdictFail, Severity: "error"},
			},
		},
	}

	total := countWarnings(results)
	if total != 4 { // 2 from Counts + 2 from Results
		t.Errorf("expected 4 warnings, got %d", total)
	}
}

func TestCountsFromResult(t *testing.T) {
	t.Run("uses cached counts", func(t *testing.T) {
		pr := policy.Result{
			Counts: policy.Counts{Passed: 5, Failed: 3, Skipped: 2, Warned: 1},
		}
		passed, failed, skipped, warned := countsFromResult(pr)
		if passed != 5 || failed != 3 || skipped != 2 || warned != 1 {
			t.Error("should use cached counts")
		}
	})

	t.Run("calculates from results when no cached counts", func(t *testing.T) {
		pr := policy.Result{
			Results: []rule.Result{
				{Verdict: rule.VerdictPass},
				{Verdict: rule.VerdictFail},
			},
		}
		passed, failed, skipped, warned := countsFromResult(pr)
		if passed != 1 || failed != 1 || skipped != 0 || warned != 0 {
			t.Errorf("expected 1,1,0,0 got %d,%d,%d,%d", passed, failed, skipped, warned)
		}
	})
}

func TestWriteRulesTable_Empty(t *testing.T) {
	var buf bytes.Buffer

	err := writeRulesTable(&buf, nil, 0, 0, 0)
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

	err := writeRulesTable(&buf, nil, 1, 2, 3)
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
	err := writeRulesTable(&buf, results, 1, 1, 0)
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
	err := writeRulesTable(&buf, results, 1, 0, 0)
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
	err := writeRulesTable(&buf, results, 0, 1, 0)
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
