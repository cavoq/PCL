package operator

import (
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type Eq struct{}

func (Eq) Name() string { return "eq" }

func (Eq) Evaluate(n *node.Node, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}
	return reflect.DeepEqual(n.Value, operands[0]), nil
}
