package rule

import (
	"fmt"
	"testing"

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

func TestRuleEvaluationUsesRegistryAwareOperator(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", 42)
	reg := operator.NewRegistry()
	reg.Register(registryAwareRuleOp{})

	result := Evaluate(root, Rule{
		ID:       "test",
		Target:   "a",
		Operator: "registryAware",
	}, reg, nil)
	if result.Verdict != VerdictPass {
		t.Fatalf("verdict = %s, want pass (%s)", result.Verdict, result.Message)
	}
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

func TestRuleEvaluationMissingTargetCanBeEmpty(t *testing.T) {
	root := node.New("root", nil)
	reg := operator.NewRegistry()
	reg.Register(operator.IsEmpty{})

	result := Evaluate(root, Rule{
		ID:       "test",
		Target:   "nonexistent",
		Operator: "isEmpty",
	}, reg, nil)
	if result.Verdict != VerdictPass {
		t.Fatalf("missing target should be empty, got %s (%s)", result.Verdict, result.Message)
	}
}

func TestRuleEvaluationApplicableMissingTargetFails(t *testing.T) {
	root := node.New("root", nil)
	root.Children["enabled"] = node.New("enabled", true)
	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	r := Rule{
		ID:       "test",
		Target:   "missing",
		Operator: "eq",
		Operands: []any{true},
		When: &Condition{
			Target:   "enabled",
			Operator: "eq",
			Operands: []any{true},
		},
	}

	res := Evaluate(root, r, reg, nil)
	if res.Verdict != VerdictFail {
		t.Fatalf("expected fail for applicable missing target, got %s", res.Verdict)
	}
	if res.Message != "target not found: missing" {
		t.Fatalf("unexpected message: %q", res.Message)
	}
}

func TestRuleEvaluationMissingWhenTarget(t *testing.T) {
	root := node.New("root", nil)
	root.Children["value"] = node.New("value", true)
	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})
	reg.Register(operator.Present{})

	tests := []struct {
		name       string
		condition  Condition
		want       string
		wantPrefix string
	}{
		{
			name:      "present condition makes rule inapplicable",
			condition: Condition{Target: "missing", Operator: "present"},
			want:      VerdictSkip,
		},
		{
			name:       "missing comparison condition is an error on applicable input",
			condition:  Condition{Target: "missing", Operator: "eq", Operands: []any{true}},
			want:       VerdictFail,
			wantPrefix: "when condition error: target not found: missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Evaluate(root, Rule{
				ID:       "test",
				Target:   "value",
				Operator: "eq",
				Operands: []any{true},
				When:     &tt.condition,
			}, reg, nil)
			if res.Verdict != tt.want {
				t.Fatalf("verdict = %s, want %s", res.Verdict, tt.want)
			}
			if tt.wantPrefix != "" && res.Message != tt.wantPrefix {
				t.Fatalf("message = %q, want %q", res.Message, tt.wantPrefix)
			}
		})
	}
}

func TestRuleEvaluationMissingTargetUsesInputNamespace(t *testing.T) {
	root := node.New("certificate", nil)
	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "missing applicable certificate field fails", target: "certificate.missing", want: VerdictFail},
		{name: "unavailable CRL input skips", target: "crl.missing", want: VerdictSkip},
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
		})
	}
}
