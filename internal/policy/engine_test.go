package policy_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

func TestPolicyPassesWhenAllRulesPass(t *testing.T) {
	root := node.New("root", nil)
	root.Children["keySize"] = node.New("keySize", 2048)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	p := policy.Policy{
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

	res := policy.Evaluate(p, root, reg)

	if res.Verdict != "pass" {
		t.Fatalf("expected verdict 'pass', got %q", res.Verdict)
	}

	if len(res.Results) != 1 {
		t.Fatalf("expected 1 rule result, got %d", len(res.Results))
	}

	if !res.Results[0].Passed {
		t.Fatalf("expected rule to pass")
	}
}

func TestPolicyFailsOnErrorSeverity(t *testing.T) {
	root := node.New("root", nil)
	root.Children["keySize"] = node.New("keySize", 1024)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	p := policy.Policy{
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

	res := policy.Evaluate(p, root, reg)

	if res.Verdict != "fail" {
		t.Fatalf("expected verdict 'fail', got %q", res.Verdict)
	}

	if res.Results[0].Passed {
		t.Fatalf("expected rule to fail")
	}
}

func TestPolicyMultipleRules(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 1)
	root.Children["b"] = node.New("b", 2)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	p := policy.Policy{
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

	res := policy.Evaluate(p, root, reg)

	if res.Verdict != "pass" {
		t.Fatalf("expected verdict 'pass' (no error failures), got %q", res.Verdict)
	}

	if len(res.Results) != 2 {
		t.Fatalf("expected 2 rule results, got %d", len(res.Results))
	}
}
