package rule

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

type Result struct {
	RuleID   string
	Passed   bool
	Message  string
	Severity string
}

func Evaluate(
	root *node.Node,
	r Rule,
	reg *operator.Registry,
) Result {

	n, _ := root.Resolve(r.Target)

	op, err := reg.Get(r.Operator)
	if err != nil {
		return Result{
			RuleID:   r.ID,
			Passed:   false,
			Message:  "operator not found",
			Severity: r.Severity,
		}
	}

	ok, err := op.Evaluate(n, r.Operands)
	if err != nil {
		return Result{
			RuleID:   r.ID,
			Passed:   false,
			Message:  err.Error(),
			Severity: r.Severity,
		}
	}

	return Result{
		RuleID:   r.ID,
		Passed:   ok,
		Severity: r.Severity,
	}
}
