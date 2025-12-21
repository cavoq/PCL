package operator

import (
	"fmt"
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type Eq struct{}

func (Eq) Name() string { return "eq" }

func (Eq) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}
	return reflect.DeepEqual(n.Value, operands[0]), nil
}

type Neq struct{}

func (Neq) Name() string { return "neq" }

func (Neq) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}
	return !reflect.DeepEqual(n.Value, operands[0]), nil
}

type Matches struct{}

func (Matches) Name() string { return "matches" }

func (Matches) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	path, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("matches operator requires a string path operand")
	}

	target, found := ctx.Root.Resolve(path)
	if !found || target == nil {
		return false, nil
	}

	return reflect.DeepEqual(n.Value, target.Value), nil
}
