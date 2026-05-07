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

// DateDiff checks that the difference between two dates is within specified limits.
// Target should be a node containing both date fields as children.
// Operands format (map):
//   - start: name/path of the start date field (child of target)
//   - end: name/path of the end date field (child of target)
//   - maxDays: maximum allowed days (optional)
//   - maxMonths: maximum allowed months (optional)
//   - minDays: minimum allowed days (optional)
//   - minHours: minimum allowed hours (optional, for OCSP validity interval)
//   - maxHours: maximum allowed hours (optional)
//
// Example YAML usage:
//   target: crl
//   operator: dateDiff
//   operands:
//     start: thisUpdate
//     end: nextUpdate
//     maxDays: 10
//
// For BR OCSP validity interval (8 hours to 10 days):
//   target: ocsp
//   operator: dateDiff
//   operands:
//     start: thisUpdate
//     end: nextUpdate
//     minHours: 8
//     maxDays: 10
type DateDiff struct{}

func (DateDiff) Name() string { return "dateDiff" }

func (DateDiff) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Parse operands
	var startPath string
	var endPath string
	var maxDays int
	var maxMonths int
	var minDays int
	var minHours int
	var maxHours int

	if len(operands) == 0 {
		return false, nil
	}

	if m, ok := operands[0].(map[string]any); ok {
		if p, ok := m["start"].(string); ok {
			startPath = p
		}
		if p, ok := m["end"].(string); ok {
			endPath = p
		}
		// Also support "from" as alias for "start"
		if p, ok := m["from"].(string); ok && startPath == "" {
			startPath = p
		}
		if d, ok := m["maxDays"].(int); ok {
			maxDays = d
		}
		if d64, ok := m["maxDays"].(int64); ok {
			maxDays = int(d64)
		}
		if f64, ok := m["maxDays"].(float64); ok {
			maxDays = int(f64)
		}
		if mVal, ok := m["maxMonths"].(int); ok {
			maxMonths = mVal
		}
		if m64, ok := m["maxMonths"].(int64); ok {
			maxMonths = int(m64)
		}
		if mf64, ok := m["maxMonths"].(float64); ok {
			maxMonths = int(mf64)
		}
		if d, ok := m["minDays"].(int); ok {
			minDays = d
		}
		// Parse hours parameters
		if h, ok := m["minHours"].(int); ok {
			minHours = h
		}
		if h64, ok := m["minHours"].(int64); ok {
			minHours = int(h64)
		}
		if hf64, ok := m["minHours"].(float64); ok {
			minHours = int(hf64)
		}
		if h, ok := m["maxHours"].(int); ok {
			maxHours = h
		}
		if h64, ok := m["maxHours"].(int64); ok {
			maxHours = int(h64)
		}
		if hf64, ok := m["maxHours"].(float64); ok {
			maxHours = int(hf64)
		}
	}

	if startPath == "" {
		return false, nil
	}

	// Resolve start date from target node's children
	startNode := resolvePath(n, startPath)
	if startNode == nil || startNode.Value == nil {
		return false, nil
	}

	startDate, ok := startNode.Value.(time.Time)
	if !ok {
		return false, nil
	}

	// Resolve end date - if endPath not specified, use target node's value
	var endDate time.Time
	if endPath != "" {
		endNode := resolvePath(n, endPath)
		if endNode == nil || endNode.Value == nil {
			return false, nil
		}
		endDate, ok = endNode.Value.(time.Time)
		if !ok {
			return false, nil
		}
	} else {
		// Use target node's value as end date
		if n.Value == nil {
			return false, nil
		}
		endDate, ok = n.Value.(time.Time)
		if !ok {
			return false, nil
		}
	}

	// Calculate difference
	diff := endDate.Sub(startDate)

	// Check maximum days
	if maxDays > 0 {
		maxDuration := time.Duration(maxDays) * 24 * time.Hour
		if diff > maxDuration {
			return false, nil
		}
	}

	// Check maximum hours
	if maxHours > 0 {
		maxDuration := time.Duration(maxHours) * time.Hour
		if diff > maxDuration {
			return false, nil
		}
	}

	// Check maximum months (using AddDate for accurate month calculation)
	if maxMonths > 0 {
		maxDate := startDate.AddDate(0, maxMonths, 0)
		if endDate.After(maxDate) {
			return false, nil
		}
	}

	// Check minimum days
	if minDays > 0 {
		minDuration := time.Duration(minDays) * 24 * time.Hour
		if diff < minDuration {
			return false, nil
		}
	}

	// Check minimum hours
	if minHours > 0 {
		minDuration := time.Duration(minHours) * time.Hour
		if diff < minDuration {
			return false, nil
		}
	}

	return true, nil
}
