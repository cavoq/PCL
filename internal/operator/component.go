package operator

import (
	"fmt"
	"net"
	"regexp"
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
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	maxLen, ok := ToInt(operands[0])
	if !ok {
		return false, fmt.Errorf("componentMaxLength requires integer max length operand")
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children (like dNSName with indexed children)
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentMaxLength(str, maxLen, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentMaxLength(str, maxLen, delimiter), nil
}

func validateComponentMaxLength(str string, maxLen int, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if len(comp) > maxLen {
			return false
		}
	}
	return true
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
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	minLen, ok := ToInt(operands[0])
	if !ok {
		return false, fmt.Errorf("componentMinLength requires integer min length operand")
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentMinLength(str, minLen, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentMinLength(str, minLen, delimiter), nil
}

func validateComponentMinLength(str string, minLen int, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if len(comp) < minLen {
			return false
		}
	}
	return true
}

// ComponentRegex validates that each component of a delimited string
// matches the specified regex pattern.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
type ComponentRegex struct{}

func (ComponentRegex) Name() string { return "componentRegex" }

func (ComponentRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("componentRegex requires string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentRegex(str, re, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentRegex(str, re, delimiter), nil
}

func validateComponentRegex(str string, re *regexp.Regexp, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if !re.MatchString(comp) {
			return false
		}
	}
	return true
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

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("componentNotRegex requires string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentNotRegex(str, re, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentNotRegex(str, re, delimiter), nil
}

func validateComponentNotRegex(str string, re *regexp.Regexp, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if re.MatchString(comp) {
			return false
		}
	}
	return true
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

	// Parse CIDR ranges from operands
	cidrs := parseCIDROperands(operands)
	if len(cidrs) == 0 {
		return false, fmt.Errorf("componentInCIDR requires valid CIDR operands")
	}

	// Handle parent node with children (iPAddress array)
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if ipInCIDRs(str, cidrs) {
				return true, nil
			}
		}
		return false, nil
	}

	// Handle single IP address string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return ipInCIDRs(str, cidrs), nil
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

	// Parse CIDR ranges from operands
	cidrs := parseCIDROperands(operands)
	if len(cidrs) == 0 {
		return false, fmt.Errorf("componentNotInCIDR requires valid CIDR operands")
	}

	// Handle parent node with children (iPAddress array)
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if ipInCIDRs(str, cidrs) {
				// Found an IP in a reserved range - validation fails
				return false, nil
			}
		}
		// All IPs are outside reserved ranges - validation passes
		return true, nil
	}

	// Handle single IP address string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return !ipInCIDRs(str, cidrs), nil
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

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("anyComponentMatches requires string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if re.MatchString(str) {
				return true, nil
			}
		}
		return false, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return re.MatchString(str), nil
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

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("noComponentMatches requires string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if re.MatchString(str) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return !re.MatchString(str), nil
}