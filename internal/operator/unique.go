package operator

import (
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

// UniqueValues checks that all children of a node have unique values.
// This is useful for validating that CRL Distribution Points, AIA URLs, etc.
// contain unique locations (no duplicates).
type UniqueValues struct{}

func (UniqueValues) Name() string { return "uniqueValues" }

func (UniqueValues) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// If the node has children, check that all child values are unique
	if len(n.Children) == 0 {
		// No children - trivially unique (or no values to check)
		return true, nil
	}

	var seen []any
	for _, child := range n.Children {
		if child.Value == nil {
			continue // Skip nil values
		}
		for _, value := range seen {
			if reflect.DeepEqual(value, child.Value) {
				return false, nil // Duplicate found
			}
		}
		seen = append(seen, child.Value)
	}

	return true, nil
}

// UniqueChildren checks that all children have unique names.
// This is useful for validating that array-like structures don't have
// duplicate entries when indexed by name.
type UniqueChildren struct{}

func (UniqueChildren) Name() string { return "uniqueChildren" }

func (UniqueChildren) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Children names are already unique in the map structure
	// But we check if there are duplicate child VALUE entries
	seen := make(map[string]bool)
	for _, child := range n.Children {
		if child.Value == nil {
			continue
		}
		// Convert value to string for comparison
		valStr, ok := child.Value.(string)
		if !ok {
			continue // Skip non-string values
		}
		if seen[valStr] {
			return false, nil // Duplicate value found
		}
		seen[valStr] = true
	}

	return true, nil
}
