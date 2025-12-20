package operator

import "github.com/cavoq/PCL/internal/node"

type Operator interface {
	Name() string
	Evaluate(n *node.Node, operands []any) (bool, error)
}
