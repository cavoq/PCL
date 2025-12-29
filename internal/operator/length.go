package operator

import (
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type MaxLength struct{}

func (MaxLength) Name() string { return "maxLength" }

func (MaxLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	maxLen, ok := ToInt(operands[0])
	if !ok {
		return false, nil
	}

	length := getLength(n)
	if length < 0 {
		return false, nil
	}

	return length <= maxLen, nil
}

type MinLength struct{}

func (MinLength) Name() string { return "minLength" }

func (MinLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	minLen, ok := ToInt(operands[0])
	if !ok {
		return false, nil
	}

	length := getLength(n)
	if length < 0 {
		return false, nil
	}

	return length >= minLen, nil
}

func getLength(n *node.Node) int {
	if n.Value == nil {
		return len(n.Children)
	}

	switch v := n.Value.(type) {
	case string:
		return len(v)
	case []byte:
		return len(v)
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map:
			return rv.Len()
		default:
			return -1
		}
	}
}
