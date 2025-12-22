package operator

import (
	"fmt"
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type In struct{}

func (In) Name() string { return "in" }

func (In) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("in requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return true, nil
		}
	}
	return false, nil
}

type NotIn struct{}

func (NotIn) Name() string { return "notIn" }

func (NotIn) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("notIn requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return false, nil
		}
	}
	return true, nil
}

type Contains struct{}

func (Contains) Name() string { return "contains" }

func (Contains) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) != 1 {
		return false, fmt.Errorf("contains requires exactly 1 operand")
	}

	target := operands[0]

	val := reflect.ValueOf(n.Value)
	if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
		for i := 0; i < val.Len(); i++ {
			if equal(val.Index(i).Interface(), target) {
				return true, nil
			}
		}
		return false, nil
	}

	if len(n.Children) > 0 {
		for _, child := range n.Children {
			if equal(child.Value, target) {
				return true, nil
			}
		}
		return false, nil
	}

	if str, ok := n.Value.(string); ok {
		if substr, ok := target.(string); ok {
			return len(str) > 0 && len(substr) > 0 && containsSubstring(str, substr), nil
		}
	}

	return false, fmt.Errorf("contains requires a slice, array, node with children, or string")
}

func equal(a, b any) bool {
	if a == b {
		return true
	}
	af, aok := toFloat64(a)
	bf, bok := toFloat64(b)
	if aok && bok {
		return af == bf
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
