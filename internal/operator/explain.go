package operator

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

// Explainer is an optional operator capability that states what an
// evaluation observed and what the operator required. n is nil when the rule
// target is absent. An empty explanation falls back to the generic one.
type Explainer interface {
	Explain(n *node.Node, ctx *EvaluationContext, operands []any) string
}

// Explain describes one evaluation of the named operator for its rule result.
// Operators without an Explainer, or without a specific explanation for these
// inputs, are described by name, outcome and operands. The explanation is
// independent of presentation so text, JSON and YAML output expose the same
// facts.
func (r *Registry) Explain(
	name string,
	n *node.Node,
	ctx *EvaluationContext,
	operands []any,
	passed bool,
) string {
	if op, err := r.Get(name); err == nil {
		if explainer, ok := op.(Explainer); ok {
			if explanation := explainer.Explain(n, ctx, operands); explanation != "" {
				return explanation
			}
		}
	}
	status := "failed"
	if passed {
		status = "passed"
	}
	explanation := fmt.Sprintf("check %s: %s", status, name)
	if len(operands) > 0 {
		explanation += "; criteria: " + diagnosticOperands(operands)
	}
	return explanation
}

func (Present) Explain(n *node.Node, _ *EvaluationContext, _ []any) string {
	return fmt.Sprintf("actual: %s; expected: present", presence(n))
}

func (Absent) Explain(n *node.Node, _ *EvaluationContext, _ []any) string {
	return fmt.Sprintf("actual: %s; expected: absent", actualValue(n))
}

func (Eq) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; expected: %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (Neq) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; disallowed: %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (In) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; allowed: %s", actualValue(n), diagnosticOperands(operands))
}

func (NotIn) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; disallowed: %s", actualValue(n), diagnosticOperands(operands))
}

func (Gt) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; required: > %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (Gte) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; minimum: %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (Lt) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; required: < %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (Lte) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; maximum: %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (Regex) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; required pattern: %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (NotRegex) Explain(n *node.Node, _ *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; disallowed pattern: %s", actualValue(n), firstDiagnosticOperand(operands))
}

func (Before) Explain(n *node.Node, ctx *EvaluationContext, operands []any) string {
	return latestAllowed(n, ctx, operands)
}

func (OnOrBefore) Explain(n *node.Node, ctx *EvaluationContext, operands []any) string {
	return latestAllowed(n, ctx, operands)
}

func (After) Explain(n *node.Node, ctx *EvaluationContext, operands []any) string {
	return earliestAllowed(n, ctx, operands)
}

func (OnOrAfter) Explain(n *node.Node, ctx *EvaluationContext, operands []any) string {
	return earliestAllowed(n, ctx, operands)
}

func latestAllowed(n *node.Node, ctx *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; latest allowed: %s", actualValue(n), comparisonTime(operands, ctx))
}

func earliestAllowed(n *node.Node, ctx *EvaluationContext, operands []any) string {
	return fmt.Sprintf("actual: %s; earliest allowed: %s", actualValue(n), comparisonTime(operands, ctx))
}

// Explain reports the compared dates when both resolve, and otherwise
// leaves the generic explanation.
func (DateDiff) Explain(target *node.Node, _ *EvaluationContext, operands []any) string {
	if target == nil || len(operands) != 1 {
		return ""
	}
	criteria, ok := operands[0].(map[string]any)
	if !ok {
		return ""
	}
	startPath, ok := diagnosticPath(criteria, "start", "from")
	if !ok {
		return ""
	}
	start := target.Lookup(startPath).Node
	if start == nil {
		return ""
	}

	end := target
	if endPath, ok := diagnosticPath(criteria, "end", "to"); ok {
		end = target.Lookup(endPath).Node
	}
	if end == nil {
		return ""
	}
	return fmt.Sprintf(
		"actual: %s to %s; limits: %s",
		diagnosticValue(start.Value),
		diagnosticValue(end.Value),
		diagnosticValue(criteria),
	)
}

func diagnosticPath(criteria map[string]any, primary, alias string) (string, bool) {
	value, ok := criteria[primary]
	if !ok {
		value, ok = criteria[alias]
	}
	path, pathOK := value.(string)
	return path, ok && pathOK && path != ""
}

func presence(n *node.Node) string {
	if n != nil {
		return "present"
	}
	return "absent"
}

func actualValue(n *node.Node) string {
	if n == nil {
		return "absent"
	}
	return diagnosticValue(n.Value)
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

func comparisonTime(operands []any, ctx *EvaluationContext) string {
	if len(operands) > 0 && operands[0] != "now" {
		return diagnosticValue(operands[0])
	}
	if ctx != nil && !ctx.Now.IsZero() {
		return diagnosticValue(ctx.Now)
	}
	return "evaluation time"
}
