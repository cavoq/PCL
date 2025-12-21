package operator

import (
	"math/big"

	"github.com/cavoq/PCL/internal/node"
)

type Positive struct{}

func (Positive) Name() string { return "positive" }

func (Positive) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil || n.Value == nil {
		return false, nil
	}

	switch v := n.Value.(type) {
	case int:
		return v > 0, nil
	case int64:
		return v > 0, nil
	case float64:
		return v > 0, nil
	case *big.Int:
		return v.Sign() > 0, nil
	case string:
		bi := new(big.Int)
		if _, ok := bi.SetString(v, 10); ok {
			return bi.Sign() > 0, nil
		}
		return false, nil
	default:
		return false, nil
	}
}
