package operator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/cavoq/PCL/internal/node"
)

type In struct{}

func (In) Name() string { return "in" }

func (In) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("in requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return true, nil
		}
	}
	return false, nil
}

type NotIn struct{}

func (NotIn) Name() string { return "notIn" }

func (NotIn) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("notIn requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return false, nil
		}
	}
	return true, nil
}

type Contains struct{}

func (Contains) Name() string { return "contains" }

func (Contains) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("contains requires at least 1 operand")
	}

	val := reflect.ValueOf(n.Value)
	if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
		for i := 0; i < val.Len(); i++ {
			if equalsAny(val.Index(i).Interface(), operands) {
				return true, nil
			}
		}
		return false, nil
	}

	if len(n.Children) > 0 {
		return childrenContain(n, operands), nil
	}

	if str, ok := n.Value.(string); ok {
		return containsSubstring(str, operands), nil
	}

	return false, fmt.Errorf("contains requires a slice, array, node with children, or string")
}

// childrenContain matches operands against child values first, then child
// names (for cases like certificatePolicies where the key is the OID).
func childrenContain(n *node.Node, operands []any) bool {
	for _, child := range n.Children {
		if equalsAny(child.Value, operands) {
			return true
		}
	}
	for name := range n.Children {
		if equalsAny(name, operands) {
			return true
		}
	}
	return false
}

func containsSubstring(str string, operands []any) bool {
	if str == "" {
		return false
	}
	for _, target := range operands {
		if substr, ok := target.(string); ok && substr != "" && strings.Contains(str, substr) {
			return true
		}
	}
	return false
}

func equalsAny(value any, operands []any) bool {
	for _, target := range operands {
		if equal(value, target) {
			return true
		}
	}
	return false
}

// DEREqualsHex checks if the node's value ([]byte, raw DER encoding) matches a hex string exactly.
// Used for Mozilla byte-for-byte DER encoding validation.
// Operand: hex string (e.g., "300d06092a864886f70d0101010500")
type DEREqualsHex struct{}

func (DEREqualsHex) Name() string { return "derEqualsHex" }

func (DEREqualsHex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("derEqualsHex requires at least 1 operand")
	}

	// Get raw bytes from node value
	rawDER, ok := n.Value.([]byte)
	if !ok {
		return false, nil
	}

	// Compare against each hex operand
	for _, op := range operands {
		hexStr, ok := op.(string)
		if !ok {
			continue
		}
		expected, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}
		if bytes.Equal(rawDER, expected) {
			return true, nil
		}
	}

	return false, nil
}

// equal reports whether a and b are deeply equal or are numerically equal
// numbers of different Go types (YAML integers against uint16 node values,
// for example). Values of different kinds never match by their string form.
func equal(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	order, ok := compareNumericValues(a, b)
	return ok && order == 0
}
