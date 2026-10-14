package operator

import (
	"reflect"
	"unicode/utf8"

	"github.com/cavoq/PCL/internal/node"
)

type MaxLength struct{}

func (MaxLength) Name() string { return "maxLength" }

func (MaxLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	return evaluateLength(n, operands, func(length, bound int) bool { return length <= bound })
}

type MinLength struct{}

func (MinLength) Name() string { return "minLength" }

func (MinLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	return evaluateLength(n, operands, func(length, bound int) bool { return length >= bound })
}

func evaluateLength(n *node.Node, operands []any, accept func(length, bound int) bool) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	bound, err := parseIntegerOperand(operands[0])
	if err != nil {
		return false, nil
	}

	length := getLength(n)
	if length < 0 {
		return false, nil
	}

	return accept(length, bound), nil
}

func getLength(n *node.Node) int {
	if n.Value == nil {
		return len(n.Children)
	}

	switch v := n.Value.(type) {
	case string:
		return utf8.RuneCountInString(v)
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
