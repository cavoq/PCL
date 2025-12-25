package rule

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

const (
	VerdictPass = "pass"
	VerdictFail = "fail"
	VerdictSkip = "skip"
)

type Result struct {
	RuleID   string `json:"rule_id" yaml:"rule_id"`
	Verdict  string `json:"verdict" yaml:"verdict"`
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message,omitempty" yaml:"message,omitempty"`
}

func Evaluate(
	root *node.Node,
	r Rule,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) Result {
	if !appliesTo(r, ctx) {
		return Result{
			RuleID:   r.ID,
			Verdict:  VerdictSkip,
			Severity: r.Severity,
		}
	}

	if r.When != nil {
		conditionMet, err := evaluateCondition(root, r.When, reg, ctx)
		if err != nil {
			return Result{
				RuleID:   r.ID,
				Verdict:  VerdictFail,
				Message:  "when condition error: " + err.Error(),
				Severity: r.Severity,
			}
		}
		if !conditionMet {
			return Result{
				RuleID:   r.ID,
				Verdict:  VerdictSkip,
				Severity: r.Severity,
			}
		}
	}

	n, _ := root.Resolve(r.Target)

	op, err := reg.Get(r.Operator)
	if err != nil {
		return Result{
			RuleID:   r.ID,
			Verdict:  VerdictFail,
			Message:  "operator not found",
			Severity: r.Severity,
		}
	}

	ok, err := op.Evaluate(n, ctx, r.Operands)
	if err != nil {
		return Result{
			RuleID:   r.ID,
			Verdict:  VerdictFail,
			Message:  err.Error(),
			Severity: r.Severity,
		}
	}

	verdict := VerdictPass
	if !ok {
		verdict = VerdictFail
	}

	return Result{
		RuleID:   r.ID,
		Verdict:  verdict,
		Severity: r.Severity,
	}
}

func evaluateCondition(
	root *node.Node,
	cond *Condition,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) (bool, error) {
	n, _ := root.Resolve(cond.Target)

	op, err := reg.Get(cond.Operator)
	if err != nil {
		return false, err
	}

	return op.Evaluate(n, ctx, cond.Operands)
}

func appliesTo(r Rule, ctx *operator.EvaluationContext) bool {
	if len(r.AppliesTo) == 0 {
		return true
	}
	if ctx == nil || ctx.Cert == nil {
		return true
	}
	for _, t := range r.AppliesTo {
		if t == ctx.Cert.Type {
			return true
		}
	}
	return false
}
