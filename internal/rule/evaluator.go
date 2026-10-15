package rule

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cavoq/PCL/internal/finding"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

const (
	VerdictPass = "pass"
	VerdictFail = "fail"
	VerdictSkip = "skip"
)

type Result struct {
	RuleID    string            `json:"rule_id" yaml:"rule_id"`
	Reference string            `json:"reference,omitempty" yaml:"reference,omitempty"`
	Verdict   string            `json:"verdict" yaml:"verdict"`
	Severity  string            `json:"severity" yaml:"severity"`
	Message   string            `json:"message,omitempty" yaml:"message,omitempty"`
	Details   string            `json:"details,omitempty" yaml:"details,omitempty"`
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
		return newResult(
			r,
			VerdictSkip,
			"",
			fmt.Sprintf("not applicable to certificate type %s; applies to: %s", kind, strings.Join(r.CertType, ", ")),
		)
	}

	if r.When != nil {
		conditionMet, err := evaluateCondition(root, r.When, reg, ctx)
		if err != nil {
			return newResult(r, VerdictFail, "when condition error: "+err.Error(), "")
		}
		if !conditionMet {
			return newResult(
				r,
				VerdictSkip,
				"",
				"condition not met: "+evaluationDetails(
					root,
					r.When.Target,
					r.When.Operator,
					r.When.Operands,
					false,
					ctx,
				),
			)
		}
	}

	ok, err := resolveAndEvaluate(root, r.Target, r.Operator, r.Operands, reg, ctx)
	details := evaluationDetails(root, r.Target, r.Operator, r.Operands, ok, ctx)
	if err != nil {
		if isTargetNotFound(err) && !node.HasInputNamespace(root, r.Target) {
			return newResult(r, VerdictSkip, "", "input unavailable; "+details)
		}
		message := err.Error()
		if r.Message != "" {
			message = r.Message
		}
		return newResult(r, VerdictFail, message, details)
	}
	verdict, message := VerdictPass, ""
	if !ok {
		verdict, message = VerdictFail, r.Message
	}
	result := newResult(r, verdict, message, details)
	result.Findings = reportedFindings(root, r, reg, ctx)
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

func newResult(r Rule, verdict, message, details string) Result {
	return Result{
		RuleID:    r.ID,
		Reference: r.Reference,
		Verdict:   verdict,
		Severity:  r.Severity,
		Message:   message,
		Details:   details,
	}
}

// evaluationDetails summarizes the observed target and the operator's
// expectation. It deliberately stays independent of presentation so text,
// JSON and YAML output expose the same diagnostic facts.
func evaluationDetails(
	root *node.Node,
	target, operatorName string,
	operands any,
	passed bool,
	ctx *operator.EvaluationContext,
) string {
	n, found := resolveTarget(root, target)
	normalized := operator.NormalizeOperands(operands)
	actual := "absent"
	if found {
		actual = diagnosticValue(n.Value)
	}

	switch operatorName {
	case "present":
		return fmt.Sprintf("actual: %s; expected: present", presence(found))
	case "absent":
		if found {
			return fmt.Sprintf("actual: %s; expected: absent", actual)
		}
		return fmt.Sprintf("actual: %s; expected: absent", presence(found))
	case "eq":
		return fmt.Sprintf("actual: %s; expected: %s", actual, firstDiagnosticOperand(normalized))
	case "neq":
		return fmt.Sprintf("actual: %s; disallowed: %s", actual, firstDiagnosticOperand(normalized))
	case "in":
		return fmt.Sprintf("actual: %s; allowed: %s", actual, diagnosticOperands(normalized))
	case "notIn":
		return fmt.Sprintf("actual: %s; disallowed: %s", actual, diagnosticOperands(normalized))
	case "gt":
		return fmt.Sprintf("actual: %s; required: > %s", actual, firstDiagnosticOperand(normalized))
	case "gte":
		return fmt.Sprintf("actual: %s; minimum: %s", actual, firstDiagnosticOperand(normalized))
	case "lt":
		return fmt.Sprintf("actual: %s; required: < %s", actual, firstDiagnosticOperand(normalized))
	case "lte":
		return fmt.Sprintf("actual: %s; maximum: %s", actual, firstDiagnosticOperand(normalized))
	case "regex":
		return fmt.Sprintf("actual: %s; required pattern: %s", actual, firstDiagnosticOperand(normalized))
	case "notRegex":
		return fmt.Sprintf("actual: %s; disallowed pattern: %s", actual, firstDiagnosticOperand(normalized))
	case "before", "onOrBefore":
		return fmt.Sprintf("actual: %s; latest allowed: %s", actual, comparisonTime(normalized, ctx))
	case "after", "onOrAfter":
		return fmt.Sprintf("actual: %s; earliest allowed: %s", actual, comparisonTime(normalized, ctx))
	case "dateDiff":
		if detail, ok := dateDiffDetails(n, normalized); ok {
			return detail
		}
	}

	status := "failed"
	if passed {
		status = "passed"
	}
	details := fmt.Sprintf("check %s: %s", status, operatorName)
	if len(normalized) > 0 {
		details += "; criteria: " + diagnosticOperands(normalized)
	}
	return details
}

func resolveTarget(root *node.Node, target string) (*node.Node, bool) {
	if root == nil {
		return nil, false
	}
	return root.Resolve(target)
}

func presence(found bool) string {
	if found {
		return "present"
	}
	return "absent"
}

func firstDiagnosticOperand(operands []any) string {
	if len(operands) == 0 {
		return "unspecified"
	}
	return diagnosticValue(operands[0])
}

func diagnosticOperands(operands []any) string {
	formatted := make([]string, len(operands))
	for index, operand := range operands {
		formatted[index] = diagnosticValue(operand)
	}
	return "[" + strings.Join(formatted, ", ") + "]"
}

func diagnosticValue(value any) string {
	var formatted string
	switch typed := value.(type) {
	case nil:
		formatted = "null"
	case string:
		if typed == "" || strings.ContainsAny(typed, " \t\r\n") {
			formatted = strconv.Quote(typed)
		} else {
			formatted = typed
		}
	case []byte:
		formatted = fmt.Sprintf("%x", typed)
	case time.Time:
		formatted = typed.Format(time.RFC3339)
	case map[string]any, []any, []string:
		encoded, err := json.Marshal(typed)
		if err == nil {
			formatted = string(encoded)
		} else {
			formatted = fmt.Sprint(typed)
		}
	default:
		formatted = fmt.Sprint(typed)
	}
	const maxDiagnosticLength = 160
	if len(formatted) > maxDiagnosticLength {
		return formatted[:maxDiagnosticLength-3] + "..."
	}
	return formatted
}

func comparisonTime(operands []any, ctx *operator.EvaluationContext) string {
	if len(operands) > 0 && operands[0] != "now" {
		return diagnosticValue(operands[0])
	}
	if ctx != nil && !ctx.Now.IsZero() {
		return diagnosticValue(ctx.Now)
	}
	return "evaluation time"
}

func dateDiffDetails(target *node.Node, operands []any) (string, bool) {
	if target == nil || len(operands) != 1 {
		return "", false
	}
	criteria, ok := operands[0].(map[string]any)
	if !ok {
		return "", false
	}
	startPath, ok := diagnosticPath(criteria, "start", "from")
	if !ok {
		return "", false
	}
	start := target.Lookup(startPath).Node
	if start == nil {
		return "", false
	}

	end := target
	if endPath, ok := diagnosticPath(criteria, "end", "to"); ok {
		end = target.Lookup(endPath).Node
	}
	if end == nil {
		return "", false
	}
	return fmt.Sprintf(
		"actual: %s to %s; limits: %s",
		diagnosticValue(start.Value),
		diagnosticValue(end.Value),
		diagnosticValue(criteria),
	), true
}

func diagnosticPath(criteria map[string]any, primary, alias string) (string, bool) {
	value, ok := criteria[primary]
	if !ok {
		value, ok = criteria[alias]
	}
	path, pathOK := value.(string)
	return path, ok && pathOK && path != ""
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
