package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

type IsCritical struct{}

func (IsCritical) Name() string { return "isCritical" }

func (IsCritical) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	critical, ok := n.Children["critical"]
	if !ok {
		return false, nil
	}

	if v, ok := critical.Value.(bool); ok {
		return v, nil
	}

	return false, nil
}

type NotCritical struct{}

func (NotCritical) Name() string { return "notCritical" }

func (NotCritical) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	critical, ok := n.Children["critical"]
	if !ok {
		return true, nil
	}

	if v, ok := critical.Value.(bool); ok {
		return !v, nil
	}

	return true, nil
}
