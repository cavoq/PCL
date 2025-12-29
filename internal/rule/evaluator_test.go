package rule

import (
	"fmt"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestRuleEvaluationPass(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{42},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictPass {
		t.Fatalf("expected rule to pass")
	}
}

func TestRuleEvaluationFail(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})
	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{100},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictFail {
		t.Fatalf("expected rule to fail")
	}
}

func TestRuleEvaluationMissingOperator(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "nonexistent",
		Operands: []any{42},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictFail {
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

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "err",
		Operands: []any{42},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictFail {
		t.Fatalf("expected rule to fail due to operator error")
	}
	if res.Message != "operator err on a: boom" {
		t.Fatalf("unexpected message: %q", res.Message)
	}
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

func TestRuleEvaluationAppliesTo_NoContext(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:        "test",
		Target:    "a",
		Operator:  "eq",
		Operands:  []any{42},
		AppliesTo: []string{"leaf"},
	}

	// With nil context, rule should still apply
	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictPass {
		t.Errorf("expected pass when context is nil, got %s", res.Verdict)
	}
}

func TestRuleEvaluationAppliesTo_Matches(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	ctx := &operator.EvaluationContext{
		Cert: &cert.Info{Type: "leaf"},
	}

	r := Rule{
		ID:        "test",
		Target:    "a",
		Operator:  "eq",
		Operands:  []any{42},
		AppliesTo: []string{"leaf", "intermediate"},
	}

	res := Evaluate(root, r, reg, ctx)

	if res.Verdict != VerdictPass {
		t.Errorf("expected pass when cert type matches, got %s", res.Verdict)
	}
}

func TestRuleEvaluationAppliesTo_NoMatch(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	ctx := &operator.EvaluationContext{
		Cert: &cert.Info{Type: "root"},
	}

	r := Rule{
		ID:        "test",
		Target:    "a",
		Operator:  "eq",
		Operands:  []any{42},
		AppliesTo: []string{"leaf"},
	}

	res := Evaluate(root, r, reg, ctx)

	if res.Verdict != VerdictSkip {
		t.Errorf("expected skip when cert type doesn't match, got %s", res.Verdict)
	}
}

func TestRuleEvaluationAppliesTo_Empty(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	ctx := &operator.EvaluationContext{
		Cert: &cert.Info{Type: "any"},
	}

	r := Rule{
		ID:        "test",
		Target:    "a",
		Operator:  "eq",
		Operands:  []any{42},
		AppliesTo: []string{}, // Empty applies to all
	}

	res := Evaluate(root, r, reg, ctx)

	if res.Verdict != VerdictPass {
		t.Errorf("expected pass when AppliesTo is empty, got %s", res.Verdict)
	}
}

func TestRuleEvaluationWhenCondition_Met(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)
	root.Children["b"] = node.New("b", true)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{42},
		When: &Condition{
			Target:   "b",
			Operator: "eq",
			Operands: []any{true},
		},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictPass {
		t.Errorf("expected pass when condition is met, got %s", res.Verdict)
	}
}

func TestRuleEvaluationWhenCondition_NotMet(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)
	root.Children["b"] = node.New("b", false)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{42},
		When: &Condition{
			Target:   "b",
			Operator: "eq",
			Operands: []any{true},
		},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictSkip {
		t.Errorf("expected skip when condition is not met, got %s", res.Verdict)
	}
}

func TestRuleEvaluationWhenCondition_OperatorNotFound(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)
	root.Children["b"] = node.New("b", true)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{42},
		When: &Condition{
			Target:   "b",
			Operator: "nonexistent",
			Operands: []any{true},
		},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictFail {
		t.Errorf("expected fail when condition operator not found, got %s", res.Verdict)
	}
	if res.Message == "" {
		t.Error("expected error message for condition failure")
	}
}

func TestRuleEvaluationWhenCondition_OperatorError(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)
	root.Children["b"] = node.New("b", 42)

	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})
	reg.Register(errOp{})

	r := Rule{
		ID:       "test",
		Target:   "a",
		Operator: "eq",
		Operands: []any{42},
		When: &Condition{
			Target:   "b",
			Operator: "err",
			Operands: []any{true},
		},
	}

	res := Evaluate(root, r, reg, nil)

	if res.Verdict != VerdictFail {
		t.Errorf("expected fail when condition operator errors, got %s", res.Verdict)
	}
}

func TestRuleEvaluationMissingTarget(t *testing.T) {
	root := node.New("root", nil)

	reg := operator.NewRegistry()
	reg.Register(operator.Present{})

	r := Rule{
		ID:       "test",
		Target:   "nonexistent",
		Operator: "present",
	}

	res := Evaluate(root, r, reg, nil)

	// The operator should receive nil node for missing target
	if res.Verdict != VerdictFail {
		t.Errorf("expected fail for missing target with 'present' operator, got %s", res.Verdict)
	}
}
