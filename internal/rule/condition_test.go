package rule

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestCompoundConditions(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", true)
	root.Children["b"] = node.New("b", false)
	root.Children["target"] = node.New("target", 1)
	reg := operator.NewRegistry()
	reg.Register(operator.Eq{})
	reg.Register(operator.Present{})

	isTrue := func(target string) Condition {
		return Condition{Target: target, Operator: "eq", Operands: []any{true}}
	}
	tests := []struct {
		name    string
		when    Condition
		verdict string
		message string
	}{
		{"allOf met", Condition{AllOf: []Condition{isTrue("a"), {Target: "b", Operator: "present"}}}, VerdictPass, ""},
		{"allOf names the first unmet condition", Condition{AllOf: []Condition{isTrue("a"), isTrue("b")}}, VerdictSkip,
			"condition not met: actual: false; expected: true"},
		{"anyOf met", Condition{AnyOf: []Condition{isTrue("b"), isTrue("a")}}, VerdictPass, ""},
		{"anyOf names every condition", Condition{AnyOf: []Condition{isTrue("b"), isTrue("missing")}}, VerdictSkip,
			"condition not met: none of: actual: false; expected: true; actual: absent; expected: true"},
		{"not of an unmet condition", Condition{Not: &Condition{AllOf: []Condition{isTrue("a"), isTrue("b")}}}, VerdictPass, ""},
		{"not of a missing target", Condition{Not: ptr(isTrue("missing"))}, VerdictPass, ""},
		{"not of a met condition", Condition{Not: ptr(isTrue("a"))}, VerdictSkip,
			"condition not met: negated condition holds (a eq)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			when := test.when
			result := Evaluate(root, Rule{ID: "test", Target: "target", Operator: "eq", Operands: []any{1}, When: &when}, reg, nil)
			if result.Verdict != test.verdict {
				t.Fatalf("verdict = %s, want %s (%v)", result.Verdict, test.verdict, result.Findings)
			}
			if test.message != "" && result.Findings[0].Message != test.message {
				t.Errorf("message = %q, want %q", result.Findings[0].Message, test.message)
			}
		})
	}
}

func ptr(condition Condition) *Condition { return &condition }
