package rule_test

import (
	"fmt"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

func TestRuleEvaluationPass(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := rule.Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{42},
	}

	res := rule.Evaluate(root, r, reg, nil)

	if res.Verdict != rule.VerdictPass {
		t.Fatalf("expected rule to pass")
	}
}

func TestRuleEvaluationFail(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})
	r := rule.Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{100},
	}

	res := rule.Evaluate(root, r, reg, nil)

	if res.Verdict != rule.VerdictFail {
		t.Fatalf("expected rule to fail")
	}
}

func TestRuleEvaluationMissingOperator(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()

	r := rule.Rule{
		ID:       "test",
		Target:   "a",
		Operator: "nonexistent",
		Operands: []any{42},
	}

	res := rule.Evaluate(root, r, reg, nil)

	if res.Verdict != rule.VerdictFail {
		t.Fatalf("expected rule to fail due to missing operator")
	}
	if res.Message != "operator not found: nonexistent" {
		t.Fatalf("unexpected message: %q", res.Message)
	}
}

type errOp struct{}

func (errOp) Name() string { return "err" }

func (errOp) Evaluate(_ *node.Node, _ *operator.EvaluationContext, _ []any) (bool, error) {
	return false, fmt.Errorf("boom")
}

func TestRuleEvaluationOperatorError(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(errOp{})

	r := rule.Rule{
		ID:       "test",
		Target:   "a",
		Operator: "err",
		Operands: []any{42},
	}

	res := rule.Evaluate(root, r, reg, nil)

	if res.Verdict != rule.VerdictFail {
		t.Fatalf("expected rule to fail due to operator error")
	}
	if res.Message != "operator err on a: boom" {
		t.Fatalf("unexpected message: %q", res.Message)
	}
}
