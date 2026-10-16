package operator

import (
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestOneOf(t *testing.T) {
	condition := func(path, operator string) map[string]any {
		return map[string]any{"path": path, "operator": operator}
	}
	present := []any{condition("a", "present"), condition("b", "present")}
	tests := []struct {
		name     string
		n        *node.Node
		operands []any
		want     bool
	}{
		{"absent target", nil, present, false},
		{"zero", node.New("target", nil), present, false},
		{"one", tree("target", nil, node.New("a", true)), present, true},
		{"two", tree("target", nil, node.New("a", true), node.New("b", true)), present, false},
		{"absence condition", node.New("target", nil), []any{condition("a", "present"), condition("b", "absent")}, true},
		{"duplicate conditions count separately", tree("target", nil, node.New("a", true)), []any{condition("a", "present"), condition("a", "present")}, false},
		{"overlapping predicates", node.New("value", 3), []any{
			map[string]any{"operator": "eq", "operands": []any{3}},
			map[string]any{"operator": "gte", "operands": []any{2}},
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := (OneOf{}).EvaluateWithRegistry(test.n, nil, test.operands, nil)
			if err != nil || got != test.want {
				t.Fatalf("oneOf = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}

func TestOneOfUsesRegistryAndPropagatesErrors(t *testing.T) {
	registry := DefaultRegistry()
	registry.Register(everyCustomOperator{})
	registry.Register(everyFailingOperator{})
	operands := []any{
		map[string]any{"operator": "everyCustom", "operands": []any{"match"}},
		map[string]any{"operator": "everyCustom", "operands": []any{"other"}},
	}
	n := node.New("target", "match")
	if got, err := registry.Evaluate("oneOf", n, nil, operands); err != nil || !got {
		t.Fatalf("custom registry: %v, %v", got, err)
	}
	// Even after two matching conditions, an evaluation error must not be
	// converted into an ordinary failed predicate.
	operands[1] = operands[0]
	operands = append(operands, map[string]any{"operator": "everyFailing"})
	if _, err := registry.Evaluate("oneOf", n, nil, operands); err == nil || !strings.Contains(err.Error(), "operands[2]") {
		t.Fatalf("nested failure = %v", err)
	}
}

func TestEveryComposesOneOf(t *testing.T) {
	operands := []any{map[string]any{"operator": "oneOf", "operands": []any{
		map[string]any{"operator": "eq", "operands": []any{1}},
		map[string]any{"operator": "eq", "operands": []any{2}},
	}}}
	if got, err := (Every{}).Evaluate(collection("values", 1, 2), nil, operands); err != nil || !got {
		t.Fatalf("every(oneOf) = %v, %v", got, err)
	}
}
