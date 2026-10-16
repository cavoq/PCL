package operator

import "github.com/cavoq/PCL/internal/node"

// AllOf uses the same conditions and missing-path semantics as AnyOf, but
// requires every condition to hold: a missing path fails its condition
// unless the condition's operator decides absence.
type AllOf struct{}

func (AllOf) Name() string { return "allOf" }

func (AllOf) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	return DefaultRegistry().Evaluate((AllOf{}).Name(), n, ctx, operands)
}

func (AllOf) ValidateOperands(operands []any, registry *Registry) error {
	return (AnyOf{}).ValidateOperands(operands, registry)
}

func (AllOf) OperandSchema() map[string]any {
	schema := (AnyOf{}).OperandSchema()
	schema["description"] = "Conditions on the target; the rule passes when every one holds."
	return schema
}

func (AllOf) EvaluateWithRegistry(n *node.Node, ctx *EvaluationContext, operands []any, registry *Registry) (bool, error) {
	if registry == nil {
		return DefaultRegistry().Evaluate((AllOf{}).Name(), n, ctx, operands)
	}
	conditions, err := parseAnyOfOperands(operands)
	if err != nil || n == nil {
		return false, err
	}
	for _, condition := range conditions {
		ok, err := evaluateAlternative(n, ctx, condition, registry)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}
