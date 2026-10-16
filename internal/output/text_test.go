package output

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cavoq/PCL/internal/finding"
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

	err := writeRulesTable(&buf, palette(true), nil, 0, false)
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

	err := writeRulesTable(&buf, palette(true), nil, 6, false)
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
		{RuleID: "rule-1", Verdict: rule.VerdictPass, Findings: []finding.Finding{
			{Code: "eq", Status: finding.StatusPass, Message: "actual: 42; expected: 42"},
		}},
		{
			RuleID:  "rule-2",
			Verdict: rule.VerdictFail,
			Message: "failed check",
			Findings: []finding.Finding{
				{Code: "eq", Status: finding.StatusFail, Message: "actual: absent; expected: true"},
			},
		},
	}

	var buf bytes.Buffer
	err := writeRulesTable(&buf, palette(true), results, 2, false)
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
	if !strings.Contains(result, "VERDICT") {
		t.Error("should contain header")
	}
	if strings.Contains(result, "DETAILS") || strings.Contains(result, "failed check") ||
		strings.Contains(result, "actual: 42") {
		t.Errorf("should hide verdict details by default:\n%s", result)
	}

	buf.Reset()
	if err := writeRulesTable(&buf, palette(false), results, 2, true); err != nil {
		t.Fatalf("write detailed rules table: %v", err)
	}
	result = buf.String()
	if strings.Contains(result, "DETAILS") {
		t.Errorf("details should not create a wide table column:\n%s", result)
	}
	for _, want := range []string{
		"└─ actual: 42; expected: 42",
		"├─ failed check",
		"└─ actual: absent; expected: true",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("detailed output should contain %q:\n%s", want, result)
		}
	}
}

func TestWrapDetailPreservesUnicode(t *testing.T) {
	value := strings.Repeat("ä", 25)
	lines := wrapDetail(value, 10)
	if got := strings.Join(lines, ""); got != value {
		t.Fatalf("wrapped value = %q, want %q", got, value)
	}
	for _, line := range lines {
		if !utf8.ValidString(line) || utf8.RuneCountInString(line) > 10 {
			t.Errorf("invalid wrapped line %q", line)
		}
	}
}

func TestWriteRulesTable_WithReference(t *testing.T) {
	results := []rule.Result{
		{RuleID: "rule-1", Verdict: rule.VerdictPass, Reference: "RFC 5280"},
	}

	var buf bytes.Buffer
	err := writeRulesTable(&buf, palette(true), results, 1, false)
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

func TestWriteRulesTableShowsRequirementLevels(t *testing.T) {
	results := []rule.Result{
		{RuleID: "rule-1", Verdict: rule.VerdictFail, Severity: rule.SeverityWarning, Requirement: rule.RequirementShould},
		{RuleID: "rule-2", Verdict: rule.VerdictPass, Severity: rule.SeverityError},
	}
	var buf bytes.Buffer
	if err := writeRulesTable(&buf, palette(false), results, 2, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(buf.String(), "\n")
	if !strings.Contains(lines[1], "SEVERITY  REQUIREMENT  RULE") || !strings.Contains(lines[3], "WARN      SHOULD       rule-1") {
		t.Errorf("table:\n%s", buf.String())
	}

	buf.Reset()
	if err := writeRulesTable(&buf, palette(false), results[1:], 1, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "REQUIREMENT") {
		t.Errorf("rules without a requirement level must not get the column:\n%s", buf.String())
	}
}

func TestWriteRulesTable_WithWarnings(t *testing.T) {
	results := []rule.Result{
		{RuleID: "rule-1", Verdict: rule.VerdictFail, Severity: "warning"},
	}

	var buf bytes.Buffer
	err := writeRulesTable(&buf, palette(true), results, 1, false)
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

func TestWriteRunMetaDescribesTheChain(t *testing.T) {
	leaf := ChainCertificate{CertType: "leaf", Subject: "CN=Leaf"}
	tests := []struct {
		name  string
		chain Chain
		want  string
	}{
		{"profile only", Chain{Certificates: []ChainCertificate{leaf}},
			"[Chain] 1 certificate(s), no trust anchor supplied\n  leaf  CN=Leaf\n"},
		{"unanchored", Chain{PathValidated: true, Certificates: []ChainCertificate{leaf}},
			"[Chain] 1 certificate(s), not anchored\n  leaf  CN=Leaf\n"},
		{"alternative", Chain{PathValidated: true, Anchored: true, Alternative: true, Certificates: []ChainCertificate{
			leaf, {CertType: "root", Subject: "CN=Root", TrustAnchor: true},
		}}, "[Chain] 2 certificate(s), anchored, alternative path (the constructed path failed validation)\n" +
			"  leaf  CN=Leaf\n  root  CN=Root (trust anchor)\n"},
	}
	for _, test := range tests {
		var buf bytes.Buffer
		if err := writeRunMeta(&buf, LintMeta{Chain: &test.chain}); err != nil {
			t.Fatal(err)
		}
		if buf.String() != test.want {
			t.Errorf("%s:\n%q\nwant\n%q", test.name, buf.String(), test.want)
		}
	}

	var buf bytes.Buffer
	if err := writeRunMeta(&buf, LintMeta{Policies: []PolicyInfo{
		{ID: "pack", Version: "2", Standard: "Standard", Edition: "2024"},
		{ID: "local"},
	}}); err != nil {
		t.Fatal(err)
	}
	if want := "[Policy] pack 2 | Standard | 2024\n[Policy] local\n"; buf.String() != want {
		t.Errorf("policies:\n%q\nwant\n%q", buf.String(), want)
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

func TestWriteRulesTableDetailsExplainFindings(t *testing.T) {
	pathFindings := []finding.Finding{
		{Code: "path.trust-anchor", Status: finding.StatusPass, Message: "the path is anchored"},
		{Code: "path.validity", Status: finding.StatusPass, Message: "certificate is valid"},
		{Code: "path.signature", Status: finding.StatusFail, Message: "certificate signature is invalid"},
	}
	tests := []struct {
		name   string
		result rule.Result
		want   string
	}{
		{
			name: "single explanation",
			result: rule.Result{Verdict: rule.VerdictSkip, Findings: []finding.Finding{
				{Code: rule.CodeCondition, Status: finding.StatusSkip, Message: "condition not met"},
			}},
			want: "└─ condition not met",
		},
		{
			name:   "failed domain findings",
			result: rule.Result{Verdict: rule.VerdictFail, Findings: pathFindings},
			want:   "└─ path.signature: certificate signature is invalid",
		},
		{
			name:   "passed domain findings",
			result: rule.Result{Verdict: rule.VerdictPass, Findings: pathFindings[:2]},
			want:   "└─ 2 findings passed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			test.result.RuleID = "rule"
			if err := writeRulesTable(&buf, palette(false), []rule.Result{test.result}, 1, true); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); !strings.Contains(got, test.want) || strings.Count(got, "─ ") != 1 {
				t.Fatalf("details should be only %q:\n%s", test.want, got)
			}
		})
	}
}
