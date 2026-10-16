package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestAllOf(t *testing.T) {
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
		{"none", node.New("target", nil), present, false},
		{"one", tree("target", nil, node.New("a", true)), present, false},
		{"both", tree("target", nil, node.New("a", true), node.New("b", true)), present, true},
		{"absence condition", tree("target", nil, node.New("a", true)), []any{condition("a", "present"), condition("b", "absent")}, true},
		{"missing path fails", node.New("value", 3), []any{
			map[string]any{"operator": "eq", "operands": []any{3}},
			map[string]any{"path": "missing", "operator": "eq", "operands": []any{3}},
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := (AllOf{}).EvaluateWithRegistry(test.n, nil, test.operands, nil)
			if err != nil || got != test.want {
				t.Fatalf("allOf = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}
