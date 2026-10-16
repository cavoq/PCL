package rule

import (
	"fmt"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

// Compound reports whether the condition combines nested conditions instead
// of checking one target.
func (c Condition) Compound() bool {
	return c.AllOf != nil || c.AnyOf != nil || c.Not != nil
}

// Leaves calls visit for every target check in the condition, depth first.
func (c *Condition) Leaves(visit func(*Condition)) {
	switch {
	case c.AllOf != nil:
		for i := range c.AllOf {
			c.AllOf[i].Leaves(visit)
		}
	case c.AnyOf != nil:
		for i := range c.AnyOf {
			c.AnyOf[i].Leaves(visit)
		}
	case c.Not != nil:
		c.Not.Leaves(visit)
	default:
		visit(c)
	}
}

func evaluateCondition(
	root *node.Node,
	cond *Condition,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) (bool, error) {
	switch {
	case cond.AllOf != nil:
		for i := range cond.AllOf {
			if ok, err := evaluateCondition(root, &cond.AllOf[i], reg, ctx); err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	case cond.AnyOf != nil:
		for i := range cond.AnyOf {
			if ok, err := evaluateCondition(root, &cond.AnyOf[i], reg, ctx); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	case cond.Not != nil:
		ok, err := evaluateCondition(root, cond.Not, reg, ctx)
		return !ok && err == nil, err
	}
	ok, err := resolveAndEvaluate(root, cond.Target, cond.Operator, cond.Operands, reg, ctx)
	// A condition on an absent target is not met: the rule is not applicable
	// to an input that lacks the field the condition inspects.
	if isTargetNotFound(err) {
		return false, nil
	}
	return ok, err
}

// explainUnmet describes why a condition that evaluated false is not met: the
// first unmet condition of allOf, every condition of anyOf, or the condition
// that not negates.
func explainUnmet(
	root *node.Node,
	cond *Condition,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) string {
	switch {
	case cond.AllOf != nil:
		for i := range cond.AllOf {
			if ok, _ := evaluateCondition(root, &cond.AllOf[i], reg, ctx); !ok {
				return explainUnmet(root, &cond.AllOf[i], reg, ctx)
			}
		}
		return "every condition holds"
	case cond.AnyOf != nil:
		parts := make([]string, 0, len(cond.AnyOf))
		for i := range cond.AnyOf {
			parts = append(parts, explainUnmet(root, &cond.AnyOf[i], reg, ctx))
		}
		return "none of: " + strings.Join(parts, "; ")
	case cond.Not != nil:
		return fmt.Sprintf("negated condition holds (%s)", describe(cond.Not))
	}
	return explain(root, cond.Target, cond.Operator, cond.Operands, false, reg, ctx)
}

// describe names a condition by its targets and operators.
func describe(cond *Condition) string {
	var parts []string
	cond.Leaves(func(leaf *Condition) {
		parts = append(parts, leaf.Target+" "+leaf.Operator)
	})
	return strings.Join(parts, ", ")
}
