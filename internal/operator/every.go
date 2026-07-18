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
//	  path: "*.distributionPoint.fullName.generalNames.*.scheme"
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
			resolution := resolvePathResult(child, parsed.path)
			targetNode = resolution.node
			if resolution.missing && !parsed.skipMissing {
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
		if targetNode.Name == "*" && len(targetNode.Children) > 0 {
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

// resolvePath resolves a dot-separated path from a node.
// Handles OID-style keys that contain dots (e.g., "2.5.29.21").
// Supports `*` wildcard to match all children at that level.
func resolvePath(n *node.Node, path string) *node.Node {
	return resolvePathResult(n, path).node
}

type pathResolution struct {
	node    *node.Node
	missing bool
}

// resolvePathResult preserves resolvePath's projected node while recording
// whether a wildcard branch failed to resolve the remaining path. Composite
// operators use that fact to distinguish a partial wildcard match from a
// complete one.
func resolvePathResult(n *node.Node, path string) pathResolution {
	if n == nil || path == "" {
		return pathResolution{node: n}
	}

	current := n
	parts := splitPath(path)

	for i := 0; i < len(parts); i++ {
		if current == nil || current.Children == nil {
			return pathResolution{}
		}

		part := parts[i]

		// Handle wildcard: collect all children and continue matching
		if part == "*" {
			virtualNode := node.New("*", nil)
			missing := false
			for _, child := range node.CollectionElements(current) {
				// Build remaining path
				if i+1 < len(parts) {
					remainingPath := combineParts(parts, i+1, len(parts))
					// If the child's name matches the next path segment,
					// skip that segment when resolving from the child
					remainingParts := splitPath(remainingPath)
					if len(remainingParts) > 0 && child.Name == remainingParts[0] {
						// Skip the matching segment
						if len(remainingParts) > 1 {
							remainingPath = combineParts(remainingParts, 1, len(remainingParts))
						} else {
							remainingPath = ""
						}
					}
					resolution := resolvePathResult(child, remainingPath)
					missing = missing || resolution.missing
					if resolution.node != nil {
						// Merge results into virtual node
						if len(resolution.node.Children) > 0 {
							for _, v := range node.CollectionElements(resolution.node) {
								virtualNode.AddElement(v)
							}
						} else {
							// Single value result
							virtualNode.AddElement(resolution.node)
						}
					} else {
						missing = true
					}
				} else {
					// * is the last part, add all children directly
					virtualNode.AddElement(child)
				}
			}
			// Return nil if virtualNode has no children (nothing matched the wildcard)
			if len(virtualNode.Children) == 0 {
				return pathResolution{missing: missing}
			}
			return pathResolution{node: virtualNode, missing: missing}
		}

		// Try to find child with exact match
		next := current.Children[part]

		// If not found and part looks like OID start (numeric),
		// try combining with subsequent parts to find OID key
		if next == nil && isOIDStart(part) && i+1 < len(parts) {
			// Try progressively combining parts until we find a match
			for j := i + 1; j <= len(parts); j++ {
				combined := combineParts(parts, i, j)
				if current.Children[combined] != nil {
					next = current.Children[combined]
					i = j - 1 // Skip the combined parts
					break
				}
			}
		}

		if next == nil {
			return pathResolution{}
		}
		current = next
	}

	return pathResolution{node: current}
}

// isOIDStart checks if a part looks like the start of an OID (numeric).
func isOIDStart(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// combineParts combines parts from i to j (exclusive) with dots.
func combineParts(parts []string, i, j int) string {
	result := parts[i]
	for k := i + 1; k < j; k++ {
		result += "." + parts[k]
	}
	return result
}

// splitPath splits a path by dots, handling numeric indices.
func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}
