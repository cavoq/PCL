package operator

import (
	"fmt"
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
		var targetNode *node.Node
		if parsed.path == "" {
			targetNode = child
		} else {
			resolution := child.Lookup(parsed.path)
			targetNode = resolution.Node
			if resolution.Partial && !parsed.skipMissing {
				return false, nil
			}
			if targetNode == nil {
				if parsed.skipMissing {
					continue
				}
				return false, nil
			}
		}

		// If target is a virtual node (from wildcard), check all its children
		if targetNode.Name == node.Wildcard && len(targetNode.Children) > 0 {
			for _, subChild := range node.CollectionElements(targetNode) {
				result, err := registry.evaluateValidated(parsed.operator, subChild, ctx, parsed.operands)
				if err != nil {
					return false, fmt.Errorf(
						"inner operator %q on child %q: %w",
						parsed.operator,
						subChild.Name,
						err,
					)
				}
				if !result {
					return false, nil
				}
			}
		} else {
			result, err := registry.evaluateValidated(parsed.operator, targetNode, ctx, parsed.operands)
			if err != nil {
				return false, fmt.Errorf(
					"inner operator %q on child %q: %w",
					parsed.operator,
					targetNode.Name,
					err,
				)
			}
			if !result {
				return false, nil
			}
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
	allowed := map[string]struct{}{
		"path": {}, "operator": {}, "check": {}, "operands": {}, "values": {}, "skipMissing": {},
	}
	var unknown []string
	for key := range object {
		if _, ok := allowed[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return everyOperands{}, fmt.Errorf("operands[0]: unknown field(s) %s", strings.Join(unknown, ", "))
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
	if _, modern := object["operator"]; modern {
		if _, legacy := object["check"]; legacy {
			return everyOperands{}, fmt.Errorf("operands[0]: operator and check are mutually exclusive")
		}
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

	if _, modern := object["operands"]; modern {
		if _, legacy := object["values"]; legacy {
			return everyOperands{}, fmt.Errorf("operands[0]: operands and values are mutually exclusive")
		}
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
