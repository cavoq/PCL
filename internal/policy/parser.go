package policy

import (
	"fmt"
	"os"
	"path/filepath"
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
	return p, nil
}

func ParseDir(dir string) ([]Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

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
