package operator

import "github.com/cavoq/PCL/internal/node"

type Operator interface {
	Name() string
	Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error)
}

var All = []Operator{
	Eq{},
	Present{},
	Gte{},
	Gt{},
	Lte{},
	Lt{},
	In{},
	NotIn{},
	Contains{},
}
