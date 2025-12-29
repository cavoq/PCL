package rule

import (
	"fmt"
	"slices"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

const (
	VerdictPass = "pass"
	VerdictFail = "fail"
	VerdictSkip = "skip"
)

type Result struct {
	RuleID    string `json:"rule_id" yaml:"rule_id"`
	Reference string `json:"reference,omitempty" yaml:"reference,omitempty"`
	Verdict   string `json:"verdict" yaml:"verdict"`
	Severity  string `json:"severity" yaml:"severity"`
	Message   string `json:"message,omitempty" yaml:"message,omitempty"`
}

func Evaluate(
	root *node.Node,
	r Rule,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) Result {
	if !appliesTo(r, ctx) {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictSkip,
			Severity:  r.Severity,
		}
	}

	if r.When != nil {
		conditionMet, err := evaluateCondition(root, r.When, reg, ctx)
		if err != nil {
			return Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   VerdictFail,
				Message:   "when condition error: " + err.Error(),
				Severity:  r.Severity,
			}
		}
		if !conditionMet {
			return Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   VerdictSkip,
				Severity:  r.Severity,
			}
		}
	}

	n, _ := root.Resolve(r.Target)

	op, err := reg.Get(r.Operator)
	if err != nil {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictFail,
			Message:   fmt.Sprintf("operator not found: %s", r.Operator),
			Severity:  r.Severity,
		}
	}

	ok, err := op.Evaluate(n, ctx, r.Operands)
	if err != nil {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictFail,
			Message:   fmt.Sprintf("operator %s on %s: %v", r.Operator, r.Target, err),
			Severity:  r.Severity,
		}
	}

	verdict := VerdictPass
	if !ok {
		verdict = VerdictFail
	}

	return Result{
		RuleID:    r.ID,
		Reference: r.Reference,
		Verdict:   verdict,
		Severity:  r.Severity,
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
		return false, fmt.Errorf("operator not found: %s", cond.Operator)
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
	return slices.Contains(r.AppliesTo, ctx.Cert.Type)
}
