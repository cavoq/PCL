package operator

import "github.com/cavoq/PCL/internal/node"

// OneOf uses the same conditions and missing-path semantics as AnyOf, but
// requires exactly one condition to hold. It counts conditions, not nodes.
type OneOf struct{}

func (OneOf) Name() string { return "oneOf" }

func (OneOf) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	return DefaultRegistry().Evaluate((OneOf{}).Name(), n, ctx, operands)
}

func (OneOf) ValidateOperands(operands []any, registry *Registry) error {
	return (AnyOf{}).ValidateOperands(operands, registry)
}

func (OneOf) OperandSchema() map[string]any {
	schema := (AnyOf{}).OperandSchema()
	schema["description"] = "Conditions on the target; the rule passes when exactly one holds."
	return schema
}

func (OneOf) EvaluateWithRegistry(n *node.Node, ctx *EvaluationContext, operands []any, registry *Registry) (bool, error) {
	if registry == nil {
		return DefaultRegistry().Evaluate((OneOf{}).Name(), n, ctx, operands)
	}
	conditions, err := parseAnyOfOperands(operands)
	if err != nil || n == nil {
		return false, err
	}
	matches := 0
	for _, condition := range conditions {
		ok, err := evaluateAlternative(n, ctx, condition, registry)
		if err != nil {
			return false, err
		}
		if ok {
			matches++
		}
	}
	return matches == 1, nil
}
