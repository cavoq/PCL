package operator

import "github.com/cavoq/PCL/internal/node"

type Present struct{}

func (Present) Name() string { return "present" }

func (Present) Evaluate(n *node.Node, _ []any) (bool, error) {
	return n != nil, nil
}
