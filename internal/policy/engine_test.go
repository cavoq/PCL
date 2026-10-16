package policy

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

func TestPolicyPassesWhenAllRulesPass(t *testing.T) {
	root := node.New("root", nil)
	root.Children["keySize"] = node.New("keySize", 2048)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	p := Policy{
		ID: "test-policy",
		Rules: []rule.Rule{
			{
				ID:       "rule-1",
				Target:   "keySize",
				Operator: "eq",
				Operands: []any{2048},
				Severity: "error",
			},
		},
	}

	res := Evaluate(p, root, reg, nil)

	if res.Verdict != "pass" {
		t.Fatalf("expected verdict 'pass', got %q", res.Verdict)
	}

	if len(res.Results) != 1 {
		t.Fatalf("expected 1 rule result, got %d", len(res.Results))
	}

	if res.Results[0].Verdict != rule.VerdictPass {
		t.Fatalf("expected rule to pass")
	}
}

func TestPolicyFailsOnErrorSeverity(t *testing.T) {
	root := node.New("root", nil)
	root.Children["keySize"] = node.New("keySize", 1024)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	p := Policy{
		ID: "test-policy",
		Rules: []rule.Rule{
			{
				ID:       "rule-1",
				Target:   "keySize",
				Operator: "eq",
				Operands: []any{2048},
				Severity: "error",
			},
		},
	}

	res := Evaluate(p, root, reg, nil)

	if res.Verdict != "fail" {
		t.Fatalf("expected verdict 'fail', got %q", res.Verdict)
	}

	if res.Results[0].Verdict != rule.VerdictFail {
		t.Fatalf("expected rule to fail")
	}
}

func TestPolicyMultipleRules(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 1)
	root.Children["b"] = node.New("b", 2)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	p := Policy{
		ID: "multi-rule-policy",
		Rules: []rule.Rule{
			{
				ID:       "rule-a",
				Target:   "a",
				Operator: "eq",
				Operands: []any{1},
				Severity: "error",
			},
			{
				ID:       "rule-b",
				Target:   "b",
				Operator: "eq",
				Operands: []any{3},
				Severity: "warning",
			},
		},
	}

	res := Evaluate(p, root, reg, nil)

	if res.Verdict != "pass" {
		t.Fatalf("expected verdict 'pass' (no error failures), got %q", res.Verdict)
	}

	if len(res.Results) != 2 {
		t.Fatalf("expected 2 rule results, got %d", len(res.Results))
	}
	if res.Results[0].RuleID != "rule-a" || res.Results[1].RuleID != "rule-b" {
		t.Fatalf("rules evaluated out of policy order: %q, %q", res.Results[0].RuleID, res.Results[1].RuleID)
	}
}

func TestVerdict(t *testing.T) {
	pass := rule.Result{Verdict: rule.VerdictPass, Severity: rule.SeverityError}
	skip := rule.Result{Verdict: rule.VerdictSkip, Severity: rule.SeverityError}
	failError := rule.Result{Verdict: rule.VerdictFail, Severity: rule.SeverityError}
	failWarning := rule.Result{Verdict: rule.VerdictFail, Severity: rule.SeverityWarning}
	inconclusiveError := rule.Result{Verdict: rule.VerdictInconclusive, Severity: rule.SeverityError}
	inconclusiveWarning := rule.Result{Verdict: rule.VerdictInconclusive, Severity: rule.SeverityWarning}
	tests := []struct {
		name    string
		results []rule.Result
		want    string
	}{
		{"no rules", nil, VerdictNotApplicable},
		{"every rule skipped", []rule.Result{skip, skip}, VerdictNotApplicable},
		{"one rule decided", []rule.Result{skip, pass}, rule.VerdictPass},
		{"only a warning failed", []rule.Result{skip, failWarning}, rule.VerdictPass},
		{"an error rule failed", []rule.Result{pass, failError, skip}, rule.VerdictFail},
		{"an error rule lacked evidence", []rule.Result{pass, inconclusiveError}, rule.VerdictInconclusive},
		{"a failure outranks missing evidence", []rule.Result{inconclusiveError, failError}, rule.VerdictFail},
		{"only a warning lacked evidence", []rule.Result{skip, inconclusiveWarning}, rule.VerdictPass},
	}
	for _, test := range tests {
		if got := Verdict(test.results); got != test.want {
			t.Errorf("%s: Verdict = %s, want %s", test.name, got, test.want)
		}
	}
}
