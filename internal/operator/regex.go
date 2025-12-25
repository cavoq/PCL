package operator

import (
	"fmt"
	"regexp"

	"github.com/cavoq/PCL/internal/node"
)

type Regex struct{}

func (Regex) Name() string { return "regex" }

func (Regex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	return matchRegex(n, operands)
}

type NotRegex struct{}

func (NotRegex) Name() string { return "notRegex" }

func (NotRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	match, err := matchRegex(n, operands)
	if err != nil {
		return false, err
	}
	return !match, nil
}

func matchRegex(n *node.Node, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("regex operator requires a string pattern operand")
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return re.MatchString(str), nil
}
