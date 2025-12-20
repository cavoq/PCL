package rule_test

import (
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

	res := rule.Evaluate(root, r, reg)

	if !res.Passed {
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

	res := rule.Evaluate(root, r, reg)

	if res.Passed {
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

	res := rule.Evaluate(root, r, reg)

	if res.Passed {
		t.Fatalf("expected rule to fail due to missing operator")
	}
}
