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
	if !certTypeMatches(r, ctx) {
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

	ok, err := resolveAndEvaluate(root, r.Target, r.Operator, r.Operands, reg, ctx)
	if err != nil {
		if _, missing := err.(targetNotFoundError); missing && !node.HasInputNamespace(root, r.Target) {
			return Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   VerdictSkip,
				Message:   err.Error(),
				Severity:  r.Severity,
			}
		}
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictFail,
			Message:   err.Error(),
			Severity:  r.Severity,
		}
	}

	verdict := VerdictPass
	message := ""
	if !ok {
		verdict = VerdictFail
		message = r.Message
	}

	return Result{
		RuleID:    r.ID,
		Reference: r.Reference,
		Verdict:   verdict,
		Severity:  r.Severity,
		Message:   message,
	}
}

func evaluateCondition(
	root *node.Node,
	cond *Condition,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) (bool, error) {
	ok, err := resolveAndEvaluate(root, cond.Target, cond.Operator, cond.Operands, reg, ctx)
	if _, missing := err.(targetNotFoundError); missing {
		if !node.HasInputNamespace(root, cond.Target) {
			return false, nil
		}
		return false, err
	}
	return ok, err
}

type targetNotFoundError struct {
	target string
}

func (err targetNotFoundError) Error() string {
	return "target not found: " + err.target
}

func resolveAndEvaluate(
	root *node.Node,
	target string,
	operatorName string,
	operands any,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) (bool, error) {
	op, err := reg.Get(operatorName)
	if err != nil {
		return false, fmt.Errorf("operator not found: %s", operatorName)
	}

	var n *node.Node
	found := false
	if root != nil {
		n, found = root.Resolve(target)
	}
	if !found {
		if _, ok := op.(operator.MissingTargetAware); !ok {
			return false, targetNotFoundError{target: target}
		}
		n = nil
	}

	ok, err := reg.Evaluate(operatorName, n, ctx, operator.NormalizeOperands(operands))
	if err != nil {
		return false, fmt.Errorf("operator %s on %s: %v", operatorName, target, err)
	}
	return ok, nil
}

func certTypeMatches(r Rule, ctx *operator.EvaluationContext) bool {
	if len(r.CertType) == 0 {
		return true
	}
	if ctx == nil || ctx.Cert == nil {
		return false
	}
	return slices.Contains(r.CertType, ctx.Cert.Type)
}
