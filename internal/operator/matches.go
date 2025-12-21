package operator

import (
	"fmt"
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

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
