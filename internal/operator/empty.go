package operator

import (
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type IsEmpty struct{}

func (IsEmpty) Name() string { return "isEmpty" }

func (IsEmpty) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return true, nil
	}

	if n.Value == nil && len(n.Children) == 0 {
		return true, nil
	}

	if n.Value == nil {
		return len(n.Children) == 0, nil
	}

	return isValueEmpty(n.Value), nil
}

type NotEmpty struct{}

func (NotEmpty) Name() string { return "notEmpty" }

func (NotEmpty) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	if n.Value == nil && len(n.Children) == 0 {
		return false, nil
	}

	if n.Value == nil {
		return len(n.Children) > 0, nil
	}

	return !isValueEmpty(n.Value), nil
}

func isValueEmpty(v any) bool {
	if v == nil {
		return true
	}

	switch val := v.(type) {
	case string:
		return val == ""
	case []byte:
		return len(val) == 0
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map:
			return rv.Len() == 0
		default:
			return false
		}
	}
}
