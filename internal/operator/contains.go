package operator

import (
	"fmt"
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type Contains struct{}

func (Contains) Name() string { return "contains" }

func (Contains) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) != 1 {
		return false, fmt.Errorf("contains requires exactly 1 operand")
	}

	val := reflect.ValueOf(n.Value)
	if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
		for i := 0; i < val.Len(); i++ {
			if equal(val.Index(i).Interface(), operands[0]) {
				return true, nil
			}
		}
		return false, nil
	}

	if len(n.Children) > 0 {
		for _, child := range n.Children {
			if equal(child.Value, operands[0]) {
				return true, nil
			}
		}
		return false, nil
	}

	if str, ok := n.Value.(string); ok {
		if substr, ok := operands[0].(string); ok {
			return len(str) > 0 && len(substr) > 0 && contains(str, substr), nil
		}
	}

	return false, fmt.Errorf("contains requires a slice, array, node with children, or string")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsString(s, substr))
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
