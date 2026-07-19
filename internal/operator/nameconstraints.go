package operator

import (
	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
)

type NameConstraintsValid struct{}

func (NameConstraintsValid) Name() string { return "nameConstraintsValid" }

func (NameConstraintsValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil {
		return false, nil
	}
	return cert.NameConstraintsValid(ctx.Cert, ctx.Chain), nil
}
