package operator

import (
	"errors"
	"strings"

	"github.com/cavoq/PCL/internal/data"
	"github.com/cavoq/PCL/internal/node"
)

// errPSLNotLoaded makes rules that need the Public Suffix List fail with an
// explanation instead of judging domains without data.
var errPSLNotLoaded = errors.New("no Public Suffix List loaded: run pcl update-data or pass --psl-file")

func requirePSL() error {
	if !data.DefaultLoader.Loaded() {
		return errPSLNotLoaded
	}
	return nil
}

// TLDRegistered checks if the domain's TLD is in IANA Root Zone Database.
// Uses external PSL data (ICANN section) for validation.
//
// Returns true if the domain's TLD exists in the ICANN domains list, and
// false for Internal Names. Like every public suffix operator it fails when
// no Public Suffix List is loaded.
//
// Useful for BR 4.2.2: "CAs SHALL NOT issue Certificates containing Internal Names"
type TLDRegistered struct{}

func (TLDRegistered) Name() string { return "tldRegistered" }

func (TLDRegistered) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if err := requirePSL(); err != nil {
		return false, err
	}
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
// Returns true if the domain is in the Public Suffix List.
//
// Useful for BR 3.2.2.6: Wildcard certificate validation
type IsPublicSuffix struct{}

func (IsPublicSuffix) Name() string { return "isPublicSuffix" }

func (IsPublicSuffix) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if err := requirePSL(); err != nil {
		return false, err
	}
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

// ComponentTLDNotRegistered checks if ANY component has unregistered TLD.
// Returns true if at least one domain is an Internal Name.
type ComponentTLDNotRegistered struct{}

func (ComponentTLDNotRegistered) Name() string { return "componentTLDNotRegistered" }

func (ComponentTLDNotRegistered) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if err := requirePSL(); err != nil {
		return false, err
	}
	if n == nil {
		return true, nil
	}

	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !data.DefaultLoader.TLDRegistered(str) {
				return true, nil
			}
		}
		return false, nil
	}

	str, ok := n.Value.(string)
	if !ok {
		return true, nil
	}
	return !data.DefaultLoader.TLDRegistered(str), nil
}

// ComponentIsPublicSuffix checks if ANY component is a public suffix.
// Useful for wildcard validation - FQDN portion must not be public suffix.
type ComponentIsPublicSuffix struct{}

func (ComponentIsPublicSuffix) Name() string { return "componentIsPublicSuffix" }

func (ComponentIsPublicSuffix) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if err := requirePSL(); err != nil {
		return false, err
	}
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

// WildcardNotPublicSuffix checks that a Wildcard Domain Name does not cover
// a public suffix: for "*.X", X must not be a public suffix under the ICANN
// section of the list (BR 3.2.2.6 excludes the PRIVATE section). Names that
// are not wildcards pass. "*.local" fails through the implicit "*" rule.
type WildcardNotPublicSuffix struct{}

func (WildcardNotPublicSuffix) Name() string { return "wildcardNotPublicSuffix" }

func (WildcardNotPublicSuffix) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if err := requirePSL(); err != nil {
		return false, err
	}
	if n == nil {
		return false, nil
	}
	name, ok := n.Value.(string)
	if !ok {
		return false, nil
	}
	covered, wildcard := strings.CutPrefix(name, "*.")
	return !wildcard || !data.DefaultLoader.IsICANNPublicSuffix(covered), nil
}
