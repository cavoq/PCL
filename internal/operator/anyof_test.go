package operator

import (
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestAnyOf(t *testing.T) {
	keyUsage := node.New("keyUsage", nil)
	keyUsage.Children["digitalSignature"] = node.New("digitalSignature", false)
	keyUsage.Children["nonRepudiation"] = node.New("nonRepudiation", true)
	bit := func(name string) map[string]any {
		return map[string]any{"path": name, "operator": "eq", "operands": []any{true}}
	}
	registry := DefaultRegistry()

	tests := []struct {
		name     string
		target   *node.Node
		operands []any
		want     bool
	}{
		{"one condition holds", keyUsage, []any{bit("digitalSignature"), bit("nonRepudiation")}, true},
		{"no condition holds", keyUsage, []any{bit("digitalSignature"), bit("keyCertSign")}, false},
		{"a missing path does not hold", keyUsage, []any{bit("keyCertSign"), bit("cRLSign")}, false},
		{"absent decides a missing path", keyUsage, []any{bit("keyCertSign"), map[string]any{"path": "cRLSign", "operator": "absent"}}, true},
		{"the target itself", node.New("value", 3), []any{
			map[string]any{"operator": "eq", "operands": []any{2}},
			map[string]any{"operator": "gte", "operands": []any{3}},
		}, true},
		{"absent target", nil, []any{bit("digitalSignature"), bit("nonRepudiation")}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := registry.Validate("anyOf", test.operands); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got, err := registry.Evaluate("anyOf", test.target, nil, test.operands)
			if err != nil || got != test.want {
				t.Fatalf("anyOf = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}

func TestAnyOfRejectsInvalidOperands(t *testing.T) {
	registry := DefaultRegistry()
	valid := map[string]any{"operator": "present"}
	for name, test := range map[string]struct {
		operands []any
		want     string
	}{
		"one condition":    {[]any{valid}, "at least two conditions"},
		"not an object":    {[]any{valid, "present"}, "expected a condition object"},
		"unknown field":    {[]any{valid, map[string]any{"operator": "present", "skipMissing": true}}, "skipMissing"},
		"unknown operator": {[]any{valid, map[string]any{"operator": "nope"}}, "nope"},
		"invalid operands": {[]any{valid, map[string]any{"operator": "eq"}}, "operands[1]"},
	} {
		for _, operator := range []string{"allOf", "anyOf", "oneOf"} {
			err := registry.Validate(operator, test.operands)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("%s/%s: error = %v, want %q", operator, name, err, test.want)
			}
		}
	}
}
