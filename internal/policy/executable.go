package policy

import (
	"fmt"

	"github.com/cavoq/PCL/internal/operator"
)

// ValidateExecutable verifies the parts of a structurally valid policy that
// depend on the operator registry used for evaluation. Keeping this separate
// from Parse allows callers to use custom registries without weakening strict
// YAML and metadata validation.
func ValidateExecutable(p Policy, registry *operator.Registry) error {
	if registry == nil {
		return fmt.Errorf("operator registry is required")
	}

	for _, candidate := range p.Rules {
		if err := registry.Validate(candidate.Operator, operator.NormalizeOperands(candidate.Operands)); err != nil {
			return fmt.Errorf("rule %s: %w", candidate.ID, err)
		}
		if candidate.When == nil {
			continue
		}
		if err := registry.Validate(
			candidate.When.Operator,
			operator.NormalizeOperands(candidate.When.Operands),
		); err != nil {
			return fmt.Errorf("rule %s: when: %w", candidate.ID, err)
		}
	}
	return nil
}

func ParseWithRegistry(data []byte, registry *operator.Registry) (Policy, error) {
	p, err := Parse(data)
	if err != nil {
		return Policy{}, err
	}
	if err := ValidateExecutable(p, registry); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func ParseFileWithRegistry(path string, registry *operator.Registry) (Policy, error) {
	p, err := ParseFile(path)
	if err != nil {
		return Policy{}, err
	}
	if err := ValidateExecutable(p, registry); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func ParseDirWithRegistry(dir string, registry *operator.Registry) ([]Policy, error) {
	policies, err := ParseDir(dir)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		if err := ValidateExecutable(p, registry); err != nil {
			return nil, fmt.Errorf("validating policy %s: %w", p.ID, err)
		}
	}
	return policies, nil
}
