package rule

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/finding"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

const (
	VerdictPass = "pass"
	VerdictFail = "fail"
	VerdictSkip = "skip"
)

// Finding codes for rules that were skipped before their operator decided.
const (
	CodeCertificateType  = "rule.certificate-type"
	CodeInputType        = "rule.input-type"
	CodeCondition        = "rule.condition"
	CodeInputUnavailable = "rule.input-unavailable"
)

// Result is the outcome of one rule. Findings explain it: the structured
// findings of a domain operator such as pathValid, or one finding whose code
// names the deciding operator and whose message states what it observed and
// required, or one rule.* finding naming why the rule was skipped.
type Result struct {
	RuleID    string            `json:"rule_id" yaml:"rule_id"`
	Reference string            `json:"reference,omitempty" yaml:"reference,omitempty"`
	Verdict   string            `json:"verdict" yaml:"verdict"`
	Severity  string            `json:"severity" yaml:"severity"`
	Message   string            `json:"message,omitempty" yaml:"message,omitempty"`
	Findings  []finding.Finding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

func Evaluate(
	root *node.Node,
	r Rule,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) Result {
	if !certTypeMatches(r, ctx) {
		kind := "unknown"
		if ctx != nil && ctx.Input.Kind != "" {
			kind = ctx.Input.Kind
		}
		return Skipped(r, CodeCertificateType, fmt.Sprintf(
			"not applicable to certificate type %s; applies to: %s",
			kind,
			strings.Join(r.CertType, ", "),
		))
	}

	if r.When != nil {
		conditionMet, err := evaluateCondition(root, r.When, reg, ctx)
		if err != nil {
			return newResult(r, VerdictFail, "when condition error: "+err.Error())
		}
		if !conditionMet {
			return Skipped(r, CodeCondition, "condition not met: "+explain(
				root,
				r.When.Target,
				r.When.Operator,
				r.When.Operands,
				false,
				reg,
				ctx,
			))
		}
	}

	ok, err := resolveAndEvaluate(root, r.Target, r.Operator, r.Operands, reg, ctx)
	explanation := explain(root, r.Target, r.Operator, r.Operands, ok, reg, ctx)
	if err != nil {
		if isTargetNotFound(err) && !node.HasInputNamespace(root, r.Target) {
			return Skipped(r, CodeInputUnavailable, "input unavailable; "+explanation)
		}
		message := err.Error()
		if r.Message != "" {
			message = r.Message
		}
		result := newResult(r, VerdictFail, message)
		result.Findings = []finding.Finding{ruleFinding(r.Operator, VerdictFail, explanation)}
		return result
	}
	verdict, message := VerdictPass, ""
	if !ok {
		verdict, message = VerdictFail, r.Message
	}
	result := newResult(r, verdict, message)
	result.Findings = reportedFindings(root, r, reg, ctx)
	if len(result.Findings) == 0 {
		result.Findings = []finding.Finding{ruleFinding(r.Operator, verdict, explanation)}
	}
	return result
}

// Skipped returns the result of a rule that was not evaluated, with one
// finding stating why.
func Skipped(r Rule, code, message string) Result {
	result := newResult(r, VerdictSkip, "")
	result.Findings = []finding.Finding{ruleFinding(code, VerdictSkip, message)}
	return result
}

// reportedFindings returns the structured findings of a rule operator that
// reports them, such as the path engine's decision.
func reportedFindings(
	root *node.Node,
	r Rule,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) []finding.Finding {
	op, err := reg.Get(r.Operator)
	if err != nil {
		return nil
	}
	reporter, ok := op.(operator.FindingReporter)
	if !ok {
		return nil
	}
	n, _ := resolveTarget(root, r.Target)
	return reporter.Findings(n, ctx, operator.NormalizeOperands(r.Operands))
}

// ruleFinding is a finding about the rule as a whole rather than one
// certificate position.
func ruleFinding(code, verdict, message string) finding.Finding {
	return finding.Finding{
		Code:             code,
		Status:           finding.Status(verdict),
		CertificateIndex: -1,
		Message:          message,
	}
}

func newResult(r Rule, verdict, message string) Result {
	return Result{
		RuleID:    r.ID,
		Reference: r.Reference,
		Verdict:   verdict,
		Severity:  r.Severity,
		Message:   message,
	}
}

// explain asks the registry to describe one evaluation of the target.
func explain(
	root *node.Node,
	target, operatorName string,
	operands any,
	passed bool,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) string {
	n, found := resolveTarget(root, target)
	if !found {
		n = nil
	}
	return reg.Explain(operatorName, n, ctx, operator.NormalizeOperands(operands), passed)
}

func resolveTarget(root *node.Node, target string) (*node.Node, bool) {
	if root == nil {
		return nil, false
	}
	return root.Resolve(target)
}

func evaluateCondition(
	root *node.Node,
	cond *Condition,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) (bool, error) {
	ok, err := resolveAndEvaluate(root, cond.Target, cond.Operator, cond.Operands, reg, ctx)
	if isTargetNotFound(err) {
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

func isTargetNotFound(err error) bool {
	var notFound targetNotFoundError
	return errors.As(err, &notFound)
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
		return false, fmt.Errorf("operator %s on %s: %w", operatorName, target, err)
	}
	return ok, nil
}

func certTypeMatches(r Rule, ctx *operator.EvaluationContext) bool {
	if len(r.CertType) == 0 {
		return true
	}
	if ctx == nil {
		return false
	}
	return slices.Contains(r.CertType, ctx.Input.Kind)
}
