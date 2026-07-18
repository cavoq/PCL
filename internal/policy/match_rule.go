package policy

import "github.com/cavoq/PCL/internal/rule"

// RuleAppliesToInput reports whether a rule's primary target belongs to the
// current evaluation input. Conditions describe dependencies and certType is
// evaluated by rule.Evaluate; neither changes the rule's execution pass.
func RuleAppliesToInput(r rule.Rule, inputType string) bool {
	return scopeForRule(r).appliesTo(inputKind(inputType))
}
