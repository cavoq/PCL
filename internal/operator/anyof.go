package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
)

// AnyOf is true when at least one of its conditions holds on the target.
// Each operand is a condition in the object form of every: a path below the
// target (empty for the target itself), an operator and its operands. A
// condition whose path does not resolve does not hold.
//
//	target: certificate.extensions.keyUsage
//	operator: anyOf
//	operands:
//	  - {path: digitalSignature, operator: eq, operands: [true]}
//	  - {path: nonRepudiation, operator: eq, operands: [true]}
type AnyOf struct{}

func (AnyOf) Name() string { return "anyOf" }

func (AnyOf) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	return DefaultRegistry().Evaluate((AnyOf{}).Name(), n, ctx, operands)
}

func (AnyOf) ValidateOperands(operands []any, registry *Registry) error {
	conditions, err := parseAnyOfOperands(operands)
	if err != nil {
		return err
	}
	for _, condition := range conditions {
		if err := validateEveryOperands(condition, registry); err != nil {
			return err
		}
	}
	return nil
}

func (AnyOf) EvaluateWithRegistry(n *node.Node, ctx *EvaluationContext, operands []any, registry *Registry) (bool, error) {
	if registry == nil {
		return DefaultRegistry().Evaluate((AnyOf{}).Name(), n, ctx, operands)
	}
	conditions, err := parseAnyOfOperands(operands)
	if err != nil || n == nil {
		return false, err
	}
	for _, condition := range conditions {
		target := n
		if condition.path != "" {
			resolution := n.Lookup(condition.path)
			if resolution.Node == nil || resolution.Partial {
				continue
			}
			target = resolution.Node
		}
		ok, err := registry.evaluateValidated(condition.operator, target, ctx, condition.operands)
		if err != nil {
			return false, fmt.Errorf("condition %s: %w", condition.invocationPath, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// OperandSchema describes the anyOf conditions.
func (AnyOf) OperandSchema() map[string]any {
	condition := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"operator"},
		"properties": map[string]any{
			"path":     map[string]any{"type": "string", "description": "Path below the target; omit for the target itself."},
			"operator": map[string]any{"type": "string", "minLength": 1, "description": "Operator of the condition."},
			"operands": map[string]any{"description": "Operands of the condition's operator."},
		},
	}
	return withDescription(map[string]any{"type": "array", "items": condition, "minItems": 2},
		"Conditions on the target; the rule passes when at least one holds.")
}

func parseAnyOfOperands(operands []any) ([]everyOperands, error) {
	if len(operands) < 2 {
		return nil, fmt.Errorf("requires at least two conditions")
	}
	conditions := make([]everyOperands, 0, len(operands))
	for index, operand := range operands {
		object, ok := operand.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("operands[%d]: expected a condition object", index)
		}
		if err := rejectUnknownFields(object, "path", "operator", "operands"); err != nil {
			return nil, fmt.Errorf("operands[%d]: %w", index, err)
		}
		condition, err := parseEveryObject(object)
		if err != nil {
			return nil, fmt.Errorf("operands[%d]: %w", index, err)
		}
		condition.invocationPath = fmt.Sprintf("operands[%d]", index)
		conditions = append(conditions, condition)
	}
	return conditions, nil
}
