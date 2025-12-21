package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
)

type In struct{}

func (In) Name() string { return "in" }

func (In) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("in requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return true, nil
		}
	}
	return false, nil
}

type NotIn struct{}

func (NotIn) Name() string { return "notIn" }

func (NotIn) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("notIn requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return false, nil
		}
	}
	return true, nil
}

func equal(a, b any) bool {
	if a == b {
		return true
	}
	af, aok := toFloat64(a)
	bf, bok := toFloat64(b)
	if aok && bok {
		return af == bf
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
