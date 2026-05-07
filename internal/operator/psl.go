package operator

import (
	"strings"

	"github.com/cavoq/PCL/internal/data"
	"github.com/cavoq/PCL/internal/node"
)

// TLDRegistered checks if the domain's TLD is in IANA Root Zone Database.
// Uses external PSL data (ICANN section) for validation.
//
// Returns true if:
//   - PSL is loaded AND domain's TLD exists in ICANN domains list
//
// Returns false if:
//   - PSL not loaded (no external data)
//   - Domain's TLD not in ICANN list (Internal Name)
//
// Useful for BR 4.2.2: "CAs SHALL NOT issue Certificates containing Internal Names"
type TLDRegistered struct{}

func (TLDRegistered) Name() string { return "tldRegistered" }

func (TLDRegistered) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Get domain value
	var domain string
	switch v := n.Value.(type) {
	case string:
		domain = v
	default:
		return false, nil
	}

	// Check via data loader
	return data.DefaultLoader.TLDRegistered(domain), nil
}

// TLDNotRegistered checks if the domain's TLD is NOT in IANA Root Zone Database.
// Inverse of TLDRegistered - useful for error rules.
//
// Returns true if domain is an Internal Name (TLD not registered).
type TLDNotRegistered struct{}

func (TLDNotRegistered) Name() string { return "tldNotRegistered" }

func (TLDNotRegistered) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	reg, err := TLDRegistered{}.Evaluate(n, ctx, operands)
	if err != nil {
		return false, err
	}
	return !reg, nil
}

// IsPublicSuffix checks if a domain is a public suffix.
// Uses external PSL data (ICANN + PRIVATE sections).
//
// Returns true if:
//   - PSL is loaded AND domain exists in public suffix list
//
// Useful for BR 3.2.2.6: Wildcard certificate validation
type IsPublicSuffix struct{}

func (IsPublicSuffix) Name() string { return "isPublicSuffix" }

func (IsPublicSuffix) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	var domain string
	switch v := n.Value.(type) {
	case string:
		domain = v
	default:
		return false, nil
	}

	// Check via data loader
	return data.DefaultLoader.IsPublicSuffix(domain), nil
}

// IsNotPublicSuffix checks if a domain is NOT a public suffix.
type IsNotPublicSuffix struct{}

func (IsNotPublicSuffix) Name() string { return "isNotPublicSuffix" }

func (IsNotPublicSuffix) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	isPS, err := IsPublicSuffix{}.Evaluate(n, ctx, operands)
	if err != nil {
		return false, err
	}
	return !isPS, nil
}

// ComponentTLDRegistered checks TLD registration for each component in an array.
// Useful for validating multiple DNS names in subjectAltName.
type ComponentTLDRegistered struct{}

func (ComponentTLDRegistered) Name() string { return "componentTLDRegistered" }

func (ComponentTLDRegistered) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Handle parent node with children (dNSName array)
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			// All domains must have registered TLDs
			if !data.DefaultLoader.TLDRegistered(str) {
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

	return data.DefaultLoader.TLDRegistered(str), nil
}

// ComponentTLDNotRegistered checks if ANY component has unregistered TLD.
// Returns true if at least one domain is an Internal Name.
type ComponentTLDNotRegistered struct{}

func (ComponentTLDNotRegistered) Name() string { return "componentTLDNotRegistered" }

func (ComponentTLDNotRegistered) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	reg, err := ComponentTLDRegistered{}.Evaluate(n, ctx, operands)
	if err != nil {
		return false, err
	}
	return !reg, nil
}

// ComponentIsPublicSuffix checks if ANY component is a public suffix.
// Useful for wildcard validation - FQDN portion must not be public suffix.
type ComponentIsPublicSuffix struct{}

func (ComponentIsPublicSuffix) Name() string { return "componentIsPublicSuffix" }

func (ComponentIsPublicSuffix) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			// Check if this domain is a public suffix
			if data.DefaultLoader.IsPublicSuffix(str) {
				return true, nil
			}
			// For wildcards, check FQDN portion
			if strings.HasPrefix(str, "*.") {
				fqdnPortion := strings.TrimPrefix(str, "*.")
				if data.DefaultLoader.IsPublicSuffix(fqdnPortion) {
					return true, nil
				}
			}
		}
		return false, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	// Direct check
	if data.DefaultLoader.IsPublicSuffix(str) {
		return true, nil
	}

	// For wildcards, check FQDN portion
	if strings.HasPrefix(str, "*.") {
		fqdnPortion := strings.TrimPrefix(str, "*.")
		return data.DefaultLoader.IsPublicSuffix(fqdnPortion), nil
	}

	return false, nil
}

// ComponentNotPublicSuffix checks ALL components are NOT public suffixes.
type ComponentNotPublicSuffix struct{}

func (ComponentNotPublicSuffix) Name() string { return "componentNotPublicSuffix" }

func (ComponentNotPublicSuffix) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	isPS, err := ComponentIsPublicSuffix{}.Evaluate(n, ctx, operands)
	if err != nil {
		return false, err
	}
	return !isPS, nil
}