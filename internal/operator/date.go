package operator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

type Before struct{}

func (Before) Name() string { return "before" }

func (Before) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	nodeTime, compareTime, err := dateComparison(n, ctx, operands)
	if err != nil {
		return false, err
	}

	return nodeTime.Before(compareTime), nil
}

type After struct{}

func (After) Name() string { return "after" }

func (After) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	nodeTime, compareTime, err := dateComparison(n, ctx, operands)
	if err != nil {
		return false, err
	}

	return nodeTime.After(compareTime), nil
}

type OnOrBefore struct{}

func (OnOrBefore) Name() string { return "onOrBefore" }

func (OnOrBefore) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	nodeTime, compareTime, err := dateComparison(n, ctx, operands)
	if err != nil {
		return false, err
	}

	return !nodeTime.After(compareTime), nil
}

type OnOrAfter struct{}

func (OnOrAfter) Name() string { return "onOrAfter" }

func (OnOrAfter) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	nodeTime, compareTime, err := dateComparison(n, ctx, operands)
	if err != nil {
		return false, err
	}

	return !nodeTime.Before(compareTime), nil
}

func dateComparison(n *node.Node, ctx *EvaluationContext, operands []any) (time.Time, time.Time, error) {
	if n == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("date target is missing")
	}

	nodeTime, err := toTime(n.Value)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	compareTime, err := getCompareTime(operands, ctx)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return nodeTime, compareTime, nil
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
//
//	target: crl
//	operator: dateDiff
//	operands:
//	  start: thisUpdate
//	  end: nextUpdate
//	  maxDays: 10
//
// For BR OCSP validity interval (8 hours to 10 days):
//
//	target: ocsp
//	operator: dateDiff
//	operands:
//	  start: thisUpdate
//	  end: nextUpdate
//	  minHours: 8
//	  maxDays: 10
type DateDiff struct{}

func (DateDiff) Name() string { return "dateDiff" }

func (DateDiff) ValidateOperands(operands []any, _ *Registry) error {
	_, err := parseDateDiffOperands(operands)
	return err
}

func (DateDiff) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	parsed, err := parseDateDiffOperands(operands)
	if err != nil {
		return false, err
	}
	if n == nil {
		return false, nil
	}

	// Resolve start date from target node's children
	startNode := resolvePath(n, parsed.startPath)
	if startNode == nil || startNode.Value == nil {
		return false, nil
	}

	startDate, ok := startNode.Value.(time.Time)
	if !ok {
		return false, nil
	}

	// Resolve end date - if endPath not specified, use target node's value
	var endDate time.Time
	if parsed.endPath != "" {
		endNode := resolvePath(n, parsed.endPath)
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
	if diff < 0 {
		return false, nil
	}

	// Check maximum days
	if parsed.maxDays > 0 {
		maxDuration := time.Duration(parsed.maxDays) * 24 * time.Hour
		if diff > maxDuration {
			return false, nil
		}
	}

	// Check maximum hours
	if parsed.maxHours > 0 {
		maxDuration := time.Duration(parsed.maxHours) * time.Hour
		if diff > maxDuration {
			return false, nil
		}
	}

	// Check maximum months (using AddDate for accurate month calculation)
	if parsed.maxMonths > 0 {
		maxDate := startDate.AddDate(0, parsed.maxMonths, 0)
		if endDate.After(maxDate) {
			return false, nil
		}
	}

	// Check minimum days
	if parsed.minDays > 0 {
		minDuration := time.Duration(parsed.minDays) * 24 * time.Hour
		if diff < minDuration {
			return false, nil
		}
	}

	// Check minimum hours
	if parsed.minHours > 0 {
		minDuration := time.Duration(parsed.minHours) * time.Hour
		if diff < minDuration {
			return false, nil
		}
	}

	return true, nil
}

type dateDiffOperands struct {
	startPath string
	endPath   string
	maxDays   int
	maxMonths int
	minDays   int
	minHours  int
	maxHours  int
}

const (
	maxDateDiffHours  = (1<<63 - 1) / int64(time.Hour)
	maxDateDiffDays   = (1<<63 - 1) / (24 * int64(time.Hour))
	maxDateDiffMonths = int64(2_000_000_000)
)

func parseDateDiffOperands(operands []any) (dateDiffOperands, error) {
	if len(operands) != 1 {
		return dateDiffOperands{}, fmt.Errorf("requires exactly 1 object operand")
	}
	object, ok := operands[0].(map[string]any)
	if !ok {
		return dateDiffOperands{}, fmt.Errorf("operands[0]: expected object")
	}

	allowed := map[string]struct{}{
		"start": {}, "from": {}, "end": {}, "maxDays": {}, "maxMonths": {},
		"minDays": {}, "minHours": {}, "maxHours": {},
	}
	var unknown []string
	for key := range object {
		if _, exists := allowed[key]; !exists {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return dateDiffOperands{}, fmt.Errorf("operands[0]: unknown field(s) %s", strings.Join(unknown, ", "))
	}
	if _, startSet := object["start"]; startSet {
		if _, fromSet := object["from"]; fromSet {
			return dateDiffOperands{}, fmt.Errorf("operands[0]: start and from are mutually exclusive")
		}
	}

	var parsed dateDiffOperands
	startKey := "start"
	startValue, exists := object["start"]
	if !exists {
		startKey = "from"
		startValue, exists = object["from"]
	}
	if !exists {
		return dateDiffOperands{}, fmt.Errorf("operands[0].start: field is required")
	}
	parsed.startPath, ok = nonEmptyDateDiffPath(startValue)
	if !ok {
		return dateDiffOperands{}, fmt.Errorf("operands[0].%s: expected non-empty string", startKey)
	}
	if endValue, exists := object["end"]; exists {
		parsed.endPath, ok = nonEmptyDateDiffPath(endValue)
		if !ok {
			return dateDiffOperands{}, fmt.Errorf("operands[0].end: expected non-empty string")
		}
	}

	fields := []struct {
		name    string
		target  *int
		maximum int64
	}{
		{name: "maxDays", target: &parsed.maxDays, maximum: maxDateDiffDays},
		{name: "maxMonths", target: &parsed.maxMonths, maximum: maxDateDiffMonths},
		{name: "minDays", target: &parsed.minDays, maximum: maxDateDiffDays},
		{name: "minHours", target: &parsed.minHours, maximum: maxDateDiffHours},
		{name: "maxHours", target: &parsed.maxHours, maximum: maxDateDiffHours},
	}
	boundCount := 0
	for _, field := range fields {
		value, exists := object[field.name]
		if !exists {
			continue
		}
		integer, err := parseIntegerOperand(value)
		if err != nil || integer <= 0 {
			return dateDiffOperands{}, fmt.Errorf("operands[0].%s: expected positive integer", field.name)
		}
		if int64(integer) > field.maximum {
			return dateDiffOperands{}, fmt.Errorf(
				"operands[0].%s: exceeds maximum supported value %d",
				field.name,
				field.maximum,
			)
		}
		*field.target = integer
		boundCount++
	}
	if boundCount == 0 {
		return dateDiffOperands{}, fmt.Errorf("operands[0]: at least one duration bound is required")
	}
	if parsed.minDays > 0 && parsed.maxDays > 0 && parsed.minDays > parsed.maxDays {
		return dateDiffOperands{}, fmt.Errorf("operands[0]: minDays must not exceed maxDays")
	}
	if parsed.minHours > 0 && parsed.maxHours > 0 && parsed.minHours > parsed.maxHours {
		return dateDiffOperands{}, fmt.Errorf("operands[0]: minHours must not exceed maxHours")
	}
	if parsed.minDays > 0 && parsed.maxHours > 0 && parsed.minDays > parsed.maxHours/24 {
		return dateDiffOperands{}, fmt.Errorf("operands[0]: minimum duration must not exceed maximum duration")
	}
	if parsed.minHours > 0 && parsed.maxDays > 0 {
		wholeDays, remainingHours := parsed.minHours/24, parsed.minHours%24
		if wholeDays > parsed.maxDays || (wholeDays == parsed.maxDays && remainingHours > 0) {
			return dateDiffOperands{}, fmt.Errorf("operands[0]: minimum duration must not exceed maximum duration")
		}
	}
	return parsed, nil
}

func nonEmptyDateDiffPath(value any) (string, bool) {
	path, ok := value.(string)
	return path, ok && path != "" && strings.TrimSpace(path) == path
}
