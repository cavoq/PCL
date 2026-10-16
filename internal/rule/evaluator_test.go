package rule

import (
	"fmt"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/finding"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

type errOp struct{}

func (errOp) Name() string { return "err" }

func (errOp) Evaluate(_ *node.Node, _ *operator.EvaluationContext, _ []any) (bool, error) {
	return false, fmt.Errorf("boom")
}

type registryAwareRuleOp struct{}

func (registryAwareRuleOp) Name() string { return "registryAware" }

func (registryAwareRuleOp) Evaluate(
	_ *node.Node,
	_ *operator.EvaluationContext,
	_ []any,
) (bool, error) {
	return false, nil
}

func (registryAwareRuleOp) EvaluateWithRegistry(
	_ *node.Node,
	_ *operator.EvaluationContext,
	_ []any,
	_ *operator.Registry,
) (bool, error) {
	return true, nil
}

func TestRuleEvaluation(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)
	root.Children["b"] = node.New("b", true)
	reg := operator.NewRegistry()
	reg.RegisterAll([]operator.Operator{
		operator.Eq{}, operator.Neq{}, operator.Present{}, operator.IsEmpty{}, errOp{}, registryAwareRuleOp{},
	})
	when := func(target, operatorName string, operands ...any) *Condition {
		return &Condition{Target: target, Operator: operatorName, Operands: operands}
	}

	tests := []struct {
		name    string
		rule    Rule
		verdict string
		// message is the expected result message when set.
		message string
	}{
		{"pass", Rule{Target: "a", Operator: "eq", Operands: []any{42}}, VerdictPass, ""},
		{"fail", Rule{Target: "a", Operator: "eq", Operands: []any{100}}, VerdictFail, ""},
		{"missing operator", Rule{Target: "a", Operator: "nonexistent", Operands: []any{42}},
			VerdictFail, "operator not found: nonexistent"},
		{"registry-aware operator", Rule{Target: "a", Operator: "registryAware"}, VerdictPass, ""},
		{"operator error", Rule{Target: "a", Operator: "err", Operands: []any{42}}, VerdictFail, "operator err on a: boom"},
		{"when condition met", Rule{Target: "a", Operator: "eq", Operands: []any{42}, When: when("b", "eq", true)},
			VerdictPass, ""},
		{"when condition not met", Rule{Target: "a", Operator: "eq", Operands: []any{42}, When: when("b", "eq", false)},
			VerdictSkip, ""},
		{"when condition operator not found", Rule{Target: "a", Operator: "eq", Operands: []any{42},
			When: when("b", "nonexistent", true)}, VerdictFail, "when condition error: operator not found: nonexistent"},
		{"when condition operator error", Rule{Target: "a", Operator: "eq", Operands: []any{42}, When: when("b", "err", true)},
			VerdictFail, ""},
		// The operator receives a nil node for a missing target.
		{"missing target is not present", Rule{Target: "nonexistent", Operator: "present"}, VerdictFail, ""},
		{"missing target is empty", Rule{Target: "nonexistent", Operator: "isEmpty"}, VerdictPass, ""},
		{"applicable missing target fails", Rule{Target: "missing", Operator: "eq", Operands: []any{true},
			When: when("b", "eq", true)}, VerdictFail, "target not found: missing"},
		{"present condition on a missing target makes the rule inapplicable", Rule{Target: "b", Operator: "eq",
			Operands: []any{true}, When: when("missing", "present")}, VerdictSkip, ""},
		{"comparison condition on a missing target makes the rule inapplicable", Rule{Target: "b", Operator: "eq",
			Operands: []any{true}, When: when("missing", "eq", true)}, VerdictSkip, ""},
		{"missing target is not equal", Rule{Target: "missing", Operator: "neq", Operands: []any{true}},
			VerdictPass, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.ID = "test"
			result := Evaluate(root, tt.rule, reg, nil)
			if result.Verdict != tt.verdict {
				t.Fatalf("verdict = %s, want %s (%s)", result.Verdict, tt.verdict, result.Message)
			}
			if tt.message != "" && result.Message != tt.message {
				t.Fatalf("message = %q, want %q", result.Message, tt.message)
			}
		})
	}
}

func TestRuleEvaluationExplainsMissingConditionTarget(t *testing.T) {
	root := node.New("root", nil)
	root.Children["b"] = node.New("b", true)
	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	result := Evaluate(root, Rule{
		ID:       "test",
		Target:   "b",
		Operator: "eq",
		Operands: []any{true},
		When:     &Condition{Target: "missing", Operator: "eq", Operands: []any{true}},
	}, reg, nil)
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %v, want one", result.Findings)
	}
	got := result.Findings[0]
	if got.Code != CodeCondition || got.Message != "condition not met: actual: absent; expected: true" {
		t.Fatalf("finding = %s %q, want %s with the absent condition target", got.Code, got.Message, CodeCondition)
	}
}

func TestRuleEvaluationFailureUsesConfiguredMessage(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})
	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{100},
		Message:  "a must equal 100",
	}

	failed := Evaluate(root, r, reg, nil)
	if failed.Message != r.Message {
		t.Fatalf("failure message = %q, want %q", failed.Message, r.Message)
	}

	r.Operands = []any{42}
	passed := Evaluate(root, r, reg, nil)
	if passed.Message != "" {
		t.Fatalf("passing result unexpectedly contains message %q", passed.Message)
	}
}

func TestRuleEvaluationExplainsEveryVerdict(t *testing.T) {
	root := node.New("root", nil)
	root.Children["algorithm"] = node.New("algorithm", "1.2.3")
	root.Children["enabled"] = node.New("enabled", true)

	reg := operator.NewRegistry()
	reg.RegisterAll([]operator.Operator{operator.Eq{}, operator.In{}})
	ctx := &operator.EvaluationContext{Input: operator.Input{Kind: "leaf"}}

	passed := Evaluate(root, Rule{
		ID:       "algorithm",
		Target:   "algorithm",
		Operator: "in",
		Operands: []any{"1.2.3", "1.2.4"},
	}, reg, ctx)
	if passed.Verdict != VerdictPass {
		t.Fatalf("passing result = %#v", passed)
	}
	wantFinding(t, passed, "in", "actual: 1.2.3; allowed: [1.2.3, 1.2.4]")

	failed := Evaluate(root, Rule{
		ID:       "missing",
		Target:   "missing",
		Operator: "eq",
		Operands: []any{true},
		Message:  "the required capability is absent",
	}, reg, ctx)
	if failed.Verdict != VerdictFail || failed.Message != "the required capability is absent" {
		t.Fatalf("failing result = %#v", failed)
	}
	wantFinding(t, failed, "eq", "actual: absent; expected: true")

	skippedType := Evaluate(root, Rule{
		ID:       "ca-only",
		Target:   "enabled",
		Operator: "eq",
		Operands: []any{true},
		CertType: []string{"intermediate", "root"},
	}, reg, ctx)
	if skippedType.Verdict != VerdictSkip {
		t.Fatalf("certificate-type skip = %#v", skippedType)
	}
	wantFinding(t, skippedType, CodeCertificateType, "not applicable to certificate type leaf; applies to: intermediate, root")

	skippedCondition := Evaluate(root, Rule{
		ID:       "conditional",
		Target:   "enabled",
		Operator: "eq",
		Operands: []any{true},
		When: &Condition{
			Target:   "algorithm",
			Operator: "eq",
			Operands: []any{"9.9.9"},
		},
	}, reg, ctx)
	if skippedCondition.Verdict != VerdictSkip {
		t.Fatalf("conditional skip = %#v", skippedCondition)
	}
	wantFinding(t, skippedCondition, CodeCondition, "condition not met: actual: 1.2.3; expected: 9.9.9")

	validity := node.New("validity", nil)
	validity.Children["notBefore"] = node.New("notBefore", time.Date(2026, 5, 26, 0, 0, 0, 0, time.UTC))
	validity.Children["notAfter"] = node.New("notAfter", time.Date(2124, 5, 26, 0, 0, 0, 0, time.UTC))
	root.Children["validity"] = validity
	reg.Register(operator.DateDiff{})
	date := Evaluate(root, Rule{
		ID:       "validity",
		Target:   "validity",
		Operator: "dateDiff",
		Operands: map[string]any{"start": "notBefore", "end": "notAfter", "maxMonths": 36},
	}, reg, ctx)
	if date.Verdict != VerdictFail {
		t.Fatalf("date result = %#v", date)
	}
	wantFinding(t, date, "dateDiff", `actual: 2026-05-26T00:00:00Z to 2124-05-26T00:00:00Z; limits: {"end":"notAfter","maxMonths":36,"start":"notBefore"}`)
}

func TestRuleEvaluationWithReference(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:        "test",
		Reference: "RFC 5280",
		Target:    "a",
		Operator:  "eq",
		Operands:  []any{42},
		Severity:  "error",
	}

	res := Evaluate(root, r, reg, nil)

	if res.Reference != "RFC 5280" {
		t.Errorf("expected reference 'RFC 5280', got %q", res.Reference)
	}
	if res.Severity != "error" {
		t.Errorf("expected severity 'error', got %q", res.Severity)
	}
}

func TestRuleEvaluationMissingTargetUsesInputNamespace(t *testing.T) {
	root := node.New("certificate", nil)
	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	tests := []struct {
		name        string
		target      string
		want        string
		wantCode    string
		wantDetails string
	}{
		{name: "missing applicable certificate field fails", target: "certificate.missing", want: VerdictFail},
		{
			name:        "unavailable CRL input skips",
			target:      "crl.missing",
			want:        VerdictSkip,
			wantCode:    CodeInputUnavailable,
			wantDetails: "input unavailable; actual: absent; expected: true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Evaluate(root, Rule{
				ID:       "test",
				Target:   tt.target,
				Operator: "eq",
				Operands: []any{true},
			}, reg, nil)
			if result.Verdict != tt.want {
				t.Fatalf("verdict = %s, want %s", result.Verdict, tt.want)
			}
			if tt.wantCode != "" {
				wantFinding(t, result, tt.wantCode, tt.wantDetails)
			}
		})
	}
}

type reportingOp struct{ pass bool }

func (reportingOp) Name() string { return "reporting" }

func (op reportingOp) Evaluate(_ *node.Node, _ *operator.EvaluationContext, _ []any) (bool, error) {
	return op.pass, nil
}

func (reportingOp) Findings(n *node.Node, _ *operator.EvaluationContext, _ []any) []finding.Finding {
	return []finding.Finding{{Code: "reported." + n.Name, Status: finding.StatusPass}}
}

func TestEvaluateAttachesReportedFindings(t *testing.T) {
	root := node.New("certificate", nil)
	root.Children["subject"] = node.New("subject", "CN=Leaf")

	for _, pass := range []bool{true, false} {
		reg := operator.NewRegistry()
		reg.RegisterAll([]operator.Operator{reportingOp{pass: pass}, operator.Present{}})

		result := Evaluate(root, Rule{ID: "reported", Target: "subject", Operator: "reporting"}, reg, nil)
		if len(result.Findings) != 1 || result.Findings[0].Code != "reported.subject" {
			t.Fatalf("pass=%v: findings = %#v, want the operator's findings for the resolved target", pass, result.Findings)
		}
		plain := Evaluate(root, Rule{ID: "plain", Target: "subject", Operator: "present"}, reg, nil)
		wantFinding(t, plain, "present", "actual: present; expected: present")
	}
}

// wantFinding checks that result is explained by exactly one rule finding.
func wantFinding(t *testing.T, result Result, code, message string) {
	t.Helper()
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one", result.Findings)
	}
	got := result.Findings[0]
	if got.Code != code || string(got.Status) != result.Verdict || got.CertificateIndex != -1 || got.Message != message {
		t.Fatalf("finding = %#v, want code %q, status %q, message %q", got, code, result.Verdict, message)
	}
}
