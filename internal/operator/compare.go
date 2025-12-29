package operator

import (
	"fmt"
	"math/big"

	"github.com/cavoq/PCL/internal/node"
)

type Gte struct{}

func (Gte) Name() string { return "gte" }

func (Gte) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) != 1 {
		return false, fmt.Errorf("gte requires exactly 1 operand")
	}
	return compareNumbers(n.Value, operands[0], func(a, b float64) bool { return a >= b })
}

type Gt struct{}

func (Gt) Name() string { return "gt" }

func (Gt) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) != 1 {
		return false, fmt.Errorf("gt requires exactly 1 operand")
	}
	return compareNumbers(n.Value, operands[0], func(a, b float64) bool { return a > b })
}

type Lte struct{}

func (Lte) Name() string { return "lte" }

func (Lte) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) != 1 {
		return false, fmt.Errorf("lte requires exactly 1 operand")
	}
	return compareNumbers(n.Value, operands[0], func(a, b float64) bool { return a <= b })
}

type Lt struct{}

func (Lt) Name() string { return "lt" }

func (Lt) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) != 1 {
		return false, fmt.Errorf("lt requires exactly 1 operand")
	}
	return compareNumbers(n.Value, operands[0], func(a, b float64) bool { return a < b })
}

func compareNumbers(val, operand any, cmp func(a, b float64) bool) (bool, error) {
	a, ok := ToFloat64(val)
	if !ok {
		return false, fmt.Errorf("value is not a number: %v", val)
	}
	b, ok := ToFloat64(operand)
	if !ok {
		return false, fmt.Errorf("operand is not a number: %v", operand)
	}
	return cmp(a, b), nil
}

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

type Odd struct{}

func (Odd) Name() string { return "odd" }

func (Odd) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil || n.Value == nil {
		return false, nil
	}

	switch v := n.Value.(type) {
	case int:
		return v%2 != 0, nil
	case int64:
		return v%2 != 0, nil
	case float64:
		return int64(v)%2 != 0, nil
	case *big.Int:
		return v.Bit(0) == 1, nil
	case string:
		bi := new(big.Int)
		if _, ok := bi.SetString(v, 10); ok {
			return bi.Bit(0) == 1, nil
		}
		return false, nil
	default:
		return false, nil
	}
}
