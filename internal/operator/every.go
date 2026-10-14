package operator

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cavoq/PCL/internal/node"
)

// Every checks that every element in an array-like node satisfies a condition.
// Operands format (map):
//   - path: sub-path relative to each element (supports `*` wildcard for nested arrays)
//   - operator: operator name to apply to each element (reuses top-level operator concept)
//   - operands: operands for the inner operator (optional)
//   - skipMissing: if true, skip elements where path doesn't exist (default: false)
//
// Example YAML usage for simple check:
//
//	target: crl.revokedCertificates
//	operator: every
//	operands:
//	  path: extensions.2.5.29.21.value
//	  operator: in
//	  operands: [1, 3, 4, 5, 9]
//
// Example YAML usage with wildcard for nested arrays:
//
//	target: certificate.extensions.cRLDistributionPoints.distributionPoints
//	operator: every
//	operands:
//	  path: "distributionPoint.fullName.generalNames.*.scheme"
//	  operator: eq
//	  operands: ["http"]
type Every struct{}

func (Every) Name() string { return "every" }

func (Every) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	registry := DefaultRegistry()
	return registry.Evaluate((Every{}).Name(), n, ctx, operands)
}

func (Every) ValidateOperands(operands []any, registry *Registry) error {
	parsed, err := parseEveryOperands(operands)
	if err != nil {
		return err
	}
	return validateEveryOperands(parsed, registry)
}

func validateEveryOperands(parsed everyOperands, registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("registry is required for nested operator validation")
	}
	if err := registry.Validate(parsed.operator, parsed.operands); err != nil {
		return fmt.Errorf("inner invocation at %s: %w", parsed.invocationPath, err)
	}
	return nil
}

func (Every) EvaluateWithRegistry(
	n *node.Node,
	ctx *EvaluationContext,
	operands []any,
	registry *Registry,
) (bool, error) {
	if registry == nil {
		registry = DefaultRegistry()
		return registry.Evaluate((Every{}).Name(), n, ctx, operands)
	}
	parsed, err := parseEveryOperands(operands)
	if err != nil {
		return false, err
	}
	if n == nil {
		return false, nil
	}

	elements := node.CollectionElements(n)
	// If node has no elements, trivially true.
	if len(elements) == 0 {
		return true, nil
	}

	// Check each logical collection element.
	for _, child := range elements {
		resolution := child.Lookup(parsed.path)
		if resolution.Partial && !parsed.skipMissing {
			return false, nil
		}
		if resolution.Node == nil {
			if parsed.skipMissing {
				continue
			}
			return false, nil
		}

		ok, err := evaluateEveryTarget(registry, parsed, resolution.Node, ctx)
		if err != nil || !ok {
			return false, err
		}
	}

	return true, nil
}

// evaluateEveryTarget applies the inner operator to target, or to each match
// when target is the synthetic node produced by a wildcard path.
func evaluateEveryTarget(
	registry *Registry,
	parsed everyOperands,
	target *node.Node,
	ctx *EvaluationContext,
) (bool, error) {
	targets := []*node.Node{target}
	if target.Name == node.Wildcard && len(target.Children) > 0 {
		targets = node.CollectionElements(target)
	}
	for _, candidate := range targets {
		result, err := registry.evaluateValidated(parsed.operator, candidate, ctx, parsed.operands)
		if err != nil {
			return false, fmt.Errorf(
				"inner operator %q on child %q: %w",
				parsed.operator,
				candidate.Name,
				err,
			)
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

type everyOperands struct {
	path           string
	operator       string
	operands       []any
	skipMissing    bool
	invocationPath string
}

func parseEveryOperands(operands []any) (everyOperands, error) {
	if len(operands) == 0 {
		return everyOperands{}, fmt.Errorf("requires operands")
	}

	if object, ok := operands[0].(map[string]any); ok {
		if len(operands) != 1 {
			return everyOperands{}, fmt.Errorf("object form requires exactly 1 operand")
		}
		return parseEveryObject(object)
	}

	if len(operands) < 2 {
		return everyOperands{}, fmt.Errorf("positional form requires path and operator operands")
	}
	path, ok := operands[0].(string)
	if !ok {
		return everyOperands{}, fmt.Errorf("operands[0]: expected path string")
	}
	if strings.TrimSpace(path) != path {
		return everyOperands{}, fmt.Errorf("operands[0]: path must not have surrounding whitespace")
	}
	innerOperator, ok := operands[1].(string)
	if !ok || strings.TrimSpace(innerOperator) == "" {
		return everyOperands{}, fmt.Errorf("operands[1]: expected non-empty operator string")
	}
	return everyOperands{
		path: path, operator: innerOperator, operands: operands[2:],
		invocationPath: "operands[2:]",
	}, nil
}

func parseEveryObject(object map[string]any) (everyOperands, error) {
	if err := rejectUnknownFields(
		object,
		"path", "operator", "check", "operands", "values", "skipMissing",
	); err != nil {
		return everyOperands{}, err
	}

	parsed := everyOperands{invocationPath: "operands[0]"}
	if value, exists := object["path"]; exists {
		path, ok := value.(string)
		if !ok {
			return everyOperands{}, fmt.Errorf("operands[0].path: expected string")
		}
		if strings.TrimSpace(path) != path {
			return everyOperands{}, fmt.Errorf("operands[0].path: must not have surrounding whitespace")
		}
		parsed.path = path
	}
	if err := rejectBothFields(object, "operator", "check"); err != nil {
		return everyOperands{}, err
	}
	operatorValue, exists := object["operator"]
	if !exists {
		operatorValue, exists = object["check"]
	}
	if !exists {
		return everyOperands{}, fmt.Errorf("operands[0].operator: field is required")
	}
	innerOperator, ok := operatorValue.(string)
	if !ok || strings.TrimSpace(innerOperator) == "" {
		return everyOperands{}, fmt.Errorf("operands[0].operator: expected non-empty string")
	}
	parsed.operator = innerOperator

	if err := rejectBothFields(object, "operands", "values"); err != nil {
		return everyOperands{}, err
	}
	if value, exists := object["operands"]; exists {
		parsed.operands = NormalizeOperands(value)
		parsed.invocationPath = "operands[0].operands"
	} else if value, exists := object["values"]; exists {
		parsed.operands = NormalizeOperands(value)
		parsed.invocationPath = "operands[0].values"
	}
	if value, exists := object["skipMissing"]; exists {
		skipMissing, ok := value.(bool)
		if !ok {
			return everyOperands{}, fmt.Errorf("operands[0].skipMissing: expected boolean")
		}
		parsed.skipMissing = skipMissing
	}
	return parsed, nil
}

// rejectUnknownFields reports fields of a structured operand outside allowed.
func rejectUnknownFields(object map[string]any, allowed ...string) error {
	var unknown []string
	for key := range object {
		if !slices.Contains(allowed, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("operands[0]: unknown field(s) %s", strings.Join(unknown, ", "))
}

// rejectBothFields reports a structured operand that sets two alternative
// spellings of the same field.
func rejectBothFields(object map[string]any, first, second string) error {
	_, firstSet := object[first]
	_, secondSet := object[second]
	if firstSet && secondSet {
		return fmt.Errorf("operands[0]: %s and %s are mutually exclusive", first, second)
	}
	return nil
}
