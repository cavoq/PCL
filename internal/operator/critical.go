package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

type IsCritical struct{}

func (IsCritical) Name() string { return "isCritical" }

func (IsCritical) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	critical, found := getCriticalValue(n)
	if !found {
		return false, nil
	}
	return critical, nil
}

type NotCritical struct{}

func (NotCritical) Name() string { return "notCritical" }

func (NotCritical) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	critical, found := getCriticalValue(n)
	if !found {
		return true, nil
	}
	return !critical, nil
}

func getCriticalValue(n *node.Node) (bool, bool) {
	if n == nil {
		return false, false
	}

	critical, ok := n.Children["critical"]
	if !ok {
		return false, false
	}

	if v, ok := critical.Value.(bool); ok {
		return v, true
	}

	return false, false
}
