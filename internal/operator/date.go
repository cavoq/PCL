package operator

import (
	"fmt"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

type Before struct{}

func (Before) Name() string { return "before" }

func (Before) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	nodeTime, err := toTime(n.Value)
	if err != nil {
		return false, err
	}

	compareTime, err := getCompareTime(operands, ctx)
	if err != nil {
		return false, err
	}

	return nodeTime.Before(compareTime), nil
}

type After struct{}

func (After) Name() string { return "after" }

func (After) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	nodeTime, err := toTime(n.Value)
	if err != nil {
		return false, err
	}

	compareTime, err := getCompareTime(operands, ctx)
	if err != nil {
		return false, err
	}

	return nodeTime.After(compareTime), nil
}

func getCompareTime(operands []any, ctx *EvaluationContext) (time.Time, error) {
	if len(operands) == 0 {
		if ctx != nil {
			return ctx.Now, nil
		}
		return time.Now(), nil
	}

	if len(operands) != 1 {
		return time.Time{}, fmt.Errorf("expected 0 or 1 operand")
	}

	if s, ok := operands[0].(string); ok && s == "now" {
		if ctx != nil {
			return ctx.Now, nil
		}
		return time.Now(), nil
	}

	return toTime(operands[0])
}

func toTime(v any) (time.Time, error) {
	switch t := v.(type) {
	case time.Time:
		return t, nil
	case string:
		formats := []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z",
			"2006-01-02",
		}
		for _, f := range formats {
			if parsed, err := time.Parse(f, t); err == nil {
				return parsed, nil
			}
		}
		return time.Time{}, fmt.Errorf("cannot parse time string: %s", t)
	default:
		return time.Time{}, fmt.Errorf("cannot convert %T to time", v)
	}
}
