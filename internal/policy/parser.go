package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cavoq/PCL/internal/rule"
	"gopkg.in/yaml.v3"
)

func ParseFile(path string) (Policy, error) {
	return parseFileWithIncludes(path, map[string]bool{})
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
	for i, inc := range p.Includes {
		if strings.TrimSpace(inc) == "" {
			return fmt.Errorf("include %d: path is required", i)
		}
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

func parseFileWithIncludes(path string, seen map[string]bool) (Policy, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Policy{}, fmt.Errorf("resolving path: %w", err)
	}
	if seen[absPath] {
		return Policy{}, fmt.Errorf("include cycle detected: %s", absPath)
	}
	seen[absPath] = true

	data, err := os.ReadFile(absPath)
	if err != nil {
		return Policy{}, fmt.Errorf("reading file: %w", err)
	}

	p, err := Parse(data)
	if err != nil {
		return Policy{}, err
	}

	if len(p.Includes) == 0 {
		return p, nil
	}

	merged := p
	merged.Rules = make([]rule.Rule, 0, len(p.Rules))
	baseDir := filepath.Dir(absPath)

	for _, inc := range p.Includes {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(baseDir, incPath)
		}
		incPolicy, err := parseFileWithIncludes(incPath, seen)
		if err != nil {
			return Policy{}, fmt.Errorf("including %s: %w", inc, err)
		}
		merged.Rules = append(merged.Rules, incPolicy.Rules...)
	}

	merged.Rules = append(merged.Rules, p.Rules...)
	return merged, nil
}
