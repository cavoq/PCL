package operator

import (
	"slices"

	"github.com/cavoq/PCL/internal/finding"
	"github.com/cavoq/PCL/internal/node"
)

// FindingReporter is an optional operator capability for decisions made by a
// domain that reports structured findings. A rule decided by such an operator
// carries the findings in its result.
type FindingReporter interface {
	Findings(n *node.Node, ctx *EvaluationContext, operands []any) []finding.Finding
}

// PathValid is the aggregate decision of the explicit-anchor path engine for
// the evaluated target certificate.
type PathValid struct{}

func (PathValid) Name() string { return "pathValid" }

func (PathValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	return ctx != nil && ctx.PathValidation != nil && ctx.PathValidation.Valid, nil
}

func (PathValid) Findings(_ *node.Node, ctx *EvaluationContext, _ []any) []finding.Finding {
	if ctx == nil || ctx.PathValidation == nil {
		return nil
	}
	return slices.Clone(ctx.PathValidation.Findings)
}
