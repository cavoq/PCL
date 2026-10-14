package operator

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/node"
)

// ComponentMaxLength validates that each component of a delimited string
// does not exceed the specified maximum length.
// This is useful for DNS label validation (max 63 chars per label),
// path segment validation, and other component-based string formats.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
//
// Operands: [maxLength, delimiter]
// - maxLength: maximum length for each component (integer)
// - delimiter: character that separates components (string, default ".")
type ComponentMaxLength struct{}

func (ComponentMaxLength) Name() string { return "componentMaxLength" }

func (ComponentMaxLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	return evaluateComponentLength(n, operands, "componentMaxLength requires integer max length operand", func(length, bound int) bool {
		return length <= bound
	})
}

// ComponentMinLength validates that each component of a delimited string
// meets the specified minimum length.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
type ComponentMinLength struct{}

func (ComponentMinLength) Name() string { return "componentMinLength" }

func (ComponentMinLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	return evaluateComponentLength(n, operands, "componentMinLength requires integer min length operand", func(length, bound int) bool {
		return length >= bound
	})
}

// ComponentRegex validates that each component of one delimited string
// matches the specified regex pattern. Collection traversal belongs to the
// Every operator, which can compose ComponentRegex for each string value.
type ComponentRegex struct{}

func (ComponentRegex) Name() string { return "componentRegex" }

func (ComponentRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	re, err := compilePatternOperand(operands[0], "componentRegex requires string pattern operand")
	if err != nil {
		return false, err
	}

	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return everyComponent(str, componentDelimiter(operands), re.MatchString), nil
}

// ComponentNotRegex validates that each component of a delimited string
// does NOT match the specified regex pattern.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
type ComponentNotRegex struct{}

func (ComponentNotRegex) Name() string { return "componentNotRegex" }

func (ComponentNotRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	re, err := compilePatternOperand(operands[0], "componentNotRegex requires string pattern operand")
	if err != nil {
		return false, err
	}

	return allComponents(n, componentDelimiter(operands), func(component string) bool {
		return !re.MatchString(component)
	}), nil
}

// ComponentInCIDR checks if any component (IP address) is within any of the specified CIDR ranges.
// Useful for checking if IP addresses fall within reserved ranges.
//
// Handles:
// - Parent node with children (like iPAddress with indexed children)
// - Single IP address string value
//
// Operands: list of CIDR strings (e.g., ["10.0.0.0/8", "192.168.0.0/16"])
// Returns true if at least one IP is within any CIDR range.
type ComponentInCIDR struct{}

func (ComponentInCIDR) Name() string { return "componentInCIDR" }

func (ComponentInCIDR) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	cidrs := parseCIDROperands(operands)
	if len(cidrs) == 0 {
		return false, fmt.Errorf("componentInCIDR requires valid CIDR operands")
	}

	values, ok := candidateStrings(n)
	if !ok {
		return false, nil
	}
	return slices.ContainsFunc(values, func(ip string) bool { return ipInCIDRs(ip, cidrs) }), nil
}

// ComponentNotInCIDR checks if all components (IP addresses) are NOT within any of the specified CIDR ranges.
// Useful for validating that IP addresses are not reserved/private.
//
// Handles:
// - Parent node with children (like iPAddress with indexed children)
// - Single IP address string value
//
// Operands: list of CIDR strings (e.g., ["10.0.0.0/8", "192.168.0.0/16"])
// Returns true if ALL IPs are outside ALL CIDR ranges.
type ComponentNotInCIDR struct{}

func (ComponentNotInCIDR) Name() string { return "componentNotInCIDR" }

func (ComponentNotInCIDR) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	cidrs := parseCIDROperands(operands)
	if len(cidrs) == 0 {
		return false, fmt.Errorf("componentNotInCIDR requires valid CIDR operands")
	}

	values, ok := candidateStrings(n)
	if !ok {
		return false, nil
	}
	return !slices.ContainsFunc(values, func(ip string) bool { return ipInCIDRs(ip, cidrs) }), nil
}

// parseCIDROperands converts operand list to CIDR network slices
func parseCIDROperands(operands []any) []*net.IPNet {
	var cidrs []*net.IPNet
	for _, op := range operands {
		cidrStr, ok := op.(string)
		if !ok {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue // Skip invalid CIDR
		}
		cidrs = append(cidrs, ipNet)
	}
	return cidrs
}

// ipInCIDRs checks if an IP address string is within any of the CIDR ranges
func ipInCIDRs(ipStr string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP address
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// AnyComponentMatches checks if ANY component (child value) matches the regex pattern.
// Unlike componentRegex which splits by delimiter, this checks the entire value.
// Useful for detecting wildcard domains (pattern "^\\*.") in SAN arrays.
//
// Handles:
// - Parent node with children: returns true if ANY child matches
// - Single string value: matches against the entire string
//
// Operands: [pattern]
// Returns true if at least one component matches.
type AnyComponentMatches struct{}

func (AnyComponentMatches) Name() string { return "anyComponentMatches" }

func (AnyComponentMatches) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	re, err := compilePatternOperand(operands[0], "anyComponentMatches requires string pattern operand")
	if err != nil {
		return false, err
	}

	values, ok := candidateStrings(n)
	if !ok {
		return false, nil
	}
	return slices.ContainsFunc(values, re.MatchString), nil
}

// NoComponentMatches checks if NO component (child value) matches the regex pattern.
// Opposite of anyComponentMatches.
//
// Handles:
// - Parent node with children: returns true if NONE of the children match
// - Single string value: returns true if the string doesn't match
//
// Operands: [pattern]
type NoComponentMatches struct{}

func (NoComponentMatches) Name() string { return "noComponentMatches" }

func (NoComponentMatches) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	re, err := compilePatternOperand(operands[0], "noComponentMatches requires string pattern operand")
	if err != nil {
		return false, err
	}

	values, ok := candidateStrings(n)
	if !ok {
		return false, nil
	}
	return !slices.ContainsFunc(values, re.MatchString), nil
}

func evaluateComponentLength(
	n *node.Node,
	operands []any,
	operandError string,
	accept func(length, bound int) bool,
) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	bound, err := parseIntegerOperand(operands[0])
	if err != nil {
		return false, errors.New(operandError)
	}

	return allComponents(n, componentDelimiter(operands), func(component string) bool {
		return accept(len(component), bound)
	}), nil
}

// candidateStrings returns the string values a component operator inspects:
// the string values of a value-less parent node's collection elements, or the
// node's own value. It reports false when a scalar node does not hold a string.
// Elements follow node.CollectionElements, so named metadata beside indexed
// elements is not treated as an element, matching every.
func candidateStrings(n *node.Node) ([]string, bool) {
	if n.Value == nil && len(n.Children) > 0 {
		elements := node.CollectionElements(n)
		values := make([]string, 0, len(elements))
		for _, child := range elements {
			if str, ok := child.Value.(string); ok {
				values = append(values, str)
			}
		}
		return values, true
	}

	str, ok := n.Value.(string)
	if !ok {
		return nil, false
	}
	return []string{str}, true
}

// allComponents reports whether every delimited component of every candidate
// string of n satisfies accept.
func allComponents(n *node.Node, delimiter string, accept func(component string) bool) bool {
	values, ok := candidateStrings(n)
	if !ok {
		return false
	}
	for _, value := range values {
		if !everyComponent(value, delimiter, accept) {
			return false
		}
	}
	return true
}

func everyComponent(value, delimiter string, accept func(component string) bool) bool {
	for _, component := range strings.Split(value, delimiter) {
		if !accept(component) {
			return false
		}
	}
	return true
}

// componentDelimiter returns the optional delimiter operand, defaulting to ".".
func componentDelimiter(operands []any) string {
	if len(operands) >= 2 {
		if delimiter, ok := operands[1].(string); ok && delimiter != "" {
			return delimiter
		}
	}
	return "."
}
