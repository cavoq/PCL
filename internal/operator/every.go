package operator

import (
	"fmt"

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
//   target: crl.revokedCertificates
//   operator: every
//   operands:
//     path: extensions.2.5.29.21.value
//     operator: in
//     operands: [1, 3, 4, 5, 9]
//
// Example YAML usage with wildcard for nested arrays:
//   target: certificate.extensions.cRLDistributionPoints.distributionPoints
//   operator: every
//   operands:
//     path: "*.distributionPoint.fullName.generalNames.*.scheme"
//     operator: eq
//     operands: ["http"]
type Every struct{}

func (Every) Name() string { return "every" }

func (Every) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Parse operands
	if len(operands) == 0 {
		return false, fmt.Errorf("every operator requires operands")
	}

	var subPath string
	var innerOp string
	var innerOperands []any
	var skipMissing bool

	if m, ok := operands[0].(map[string]any); ok {
		if p, ok := m["path"].(string); ok {
			subPath = p
		}
		// Use "operator" for inner operator (consistent naming)
		if op, ok := m["operator"].(string); ok {
			innerOp = op
		}
		// Also support legacy "check" for backwards compatibility
		if c, ok := m["check"].(string); ok && innerOp == "" {
			innerOp = c
		}
		if v, ok := m["operands"]; ok {
			switch val := v.(type) {
			case []any:
				innerOperands = val
			case map[string]any:
				innerOperands = []any{val}
			default:
				innerOperands = []any{val}
			}
		}
		// Also support legacy "values" for backwards compatibility
		if vs, ok := m["values"]; ok && len(innerOperands) == 0 {
			switch val := vs.(type) {
			case []any:
				innerOperands = val
			default:
				innerOperands = []any{val}
			}
		}
		if s, ok := m["skipMissing"].(bool); ok {
			skipMissing = s
		}
	} else if len(operands) >= 2 {
		// Alternative: parse as [path, operator, operands...]
		if p, ok := operands[0].(string); ok {
			subPath = p
		}
		if op, ok := operands[1].(string); ok {
			innerOp = op
		}
		if len(operands) > 2 {
			innerOperands = operands[2:]
		}
	}

	if innerOp == "" {
		return false, fmt.Errorf("every operator requires 'operator' operand")
	}

	registry := DefaultRegistry()
	op, err := registry.Get(innerOp)
	if err != nil {
		return false, fmt.Errorf("every: unknown operator '%s'", innerOp)
	}

	// If node has no children, trivially true
	if len(n.Children) == 0 {
		return true, nil
	}

	// Check each child
	for _, child := range n.Children {
		if child == nil {
			continue
		}

		var targetNode *node.Node
		if subPath == "" {
			targetNode = child
		} else {
			targetNode = resolvePath(child, subPath)
			if targetNode == nil {
				if skipMissing {
					continue
				}
				return false, nil
			}
		}

		// If target is a virtual node (from wildcard), check all its children
		if targetNode.Name == "*" && len(targetNode.Children) > 0 {
			for _, subChild := range targetNode.Children {
				if subChild == nil {
					continue
				}
				result, err := op.Evaluate(subChild, ctx, innerOperands)
				if err != nil {
					return false, err
				}
				if !result {
					return false, nil
				}
			}
		} else {
			result, err := op.Evaluate(targetNode, ctx, innerOperands)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
	}

	return true, nil
}

// resolvePath resolves a dot-separated path from a node.
// Handles OID-style keys that contain dots (e.g., "2.5.29.21").
// Supports `*` wildcard to match all children at that level.
func resolvePath(n *node.Node, path string) *node.Node {
	if n == nil || path == "" {
		return n
	}

	current := n
	parts := splitPath(path)

	for i := 0; i < len(parts); i++ {
		if current == nil || current.Children == nil {
			return nil
		}

		part := parts[i]

		// Handle wildcard: collect all children and continue matching
		if part == "*" {
			virtualNode := node.New("*", nil)
			for _, child := range current.Children {
				if child == nil {
					continue
				}
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
					result := resolvePath(child, remainingPath)
					if result != nil {
						// Merge results into virtual node
						if len(result.Children) > 0 {
							for _, v := range result.Children {
								virtualNode.Children[fmt.Sprintf("%d", len(virtualNode.Children))] = v
							}
						} else {
							// Single value result
							virtualNode.Children[fmt.Sprintf("%d", len(virtualNode.Children))] = result
						}
					}
				} else {
					// * is the last part, add all children directly
					virtualNode.Children[fmt.Sprintf("%d", len(virtualNode.Children))] = child
				}
			}
			// Return nil if virtualNode has no children (nothing matched the wildcard)
			if len(virtualNode.Children) == 0 {
				return nil
			}
			return virtualNode
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
			return nil
		}
		current = next
	}

	return current
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