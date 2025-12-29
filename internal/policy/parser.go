package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func ParseFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("reading file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parsing yaml: %w", err)
	}
	if err := validatePolicy(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func ParseDir(dir string) ([]Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	policies := make([]Policy, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		p, err := ParseFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		policies = append(policies, p)
	}

	return policies, nil
}

func validatePolicy(p Policy) error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("policy id is required")
	}
	for i, r := range p.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("rule %d: id is required", i)
		}
		if strings.TrimSpace(r.Target) == "" {
			return fmt.Errorf("rule %s: target is required", r.ID)
		}
		if strings.TrimSpace(r.Operator) == "" {
			return fmt.Errorf("rule %s: operator is required", r.ID)
		}
		if r.When != nil {
			if strings.TrimSpace(r.When.Target) == "" {
				return fmt.Errorf("rule %s: when.target is required", r.ID)
			}
			if strings.TrimSpace(r.When.Operator) == "" {
				return fmt.Errorf("rule %s: when.operator is required", r.ID)
			}
		}
	}
	return nil
}
