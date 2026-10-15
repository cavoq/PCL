package operator

import (
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

func TestRegistryExplain(t *testing.T) {
	reg := DefaultRegistry()
	value := node.New("value", "1.2.3")
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ctx := &EvaluationContext{Now: now}

	tests := []struct {
		name     string
		operator string
		n        *node.Node
		operands []any
		passed   bool
		want     string
	}{
		{name: "present", operator: "present", n: value, passed: true, want: "actual: present; expected: present"},
		{name: "absent target", operator: "absent", want: "actual: absent; expected: absent"},
		{name: "eq", operator: "eq", n: value, operands: []any{"1.2.4"}, want: "actual: 1.2.3; expected: 1.2.4"},
		{name: "notIn", operator: "notIn", n: value, operands: []any{"a", "b c"}, want: `actual: 1.2.3; disallowed: [a, "b c"]`},
		{name: "gte", operator: "gte", n: node.New("size", 1024), operands: []any{2048}, want: "actual: 1024; minimum: 2048"},
		{name: "before now", operator: "before", n: node.New("t", now), operands: []any{"now"}, want: "actual: 2026-06-01T00:00:00Z; latest allowed: 2026-06-01T00:00:00Z"},
		{name: "dateDiff without dates", operator: "dateDiff", n: value, operands: []any{map[string]any{"start": "missing"}}, want: `check failed: dateDiff; criteria: [{"start":"missing"}]`},
		{name: "operator without explainer", operator: "signatureValid", passed: true, want: "check passed: signatureValid"},
		{name: "unknown operator", operator: "noSuchOperator", operands: []any{1}, want: "check failed: noSuchOperator; criteria: [1]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := reg.Explain(test.operator, test.n, ctx, test.operands, test.passed); got != test.want {
				t.Fatalf("Explain() = %q, want %q", got, test.want)
			}
		})
	}
}
