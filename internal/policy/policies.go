package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func GetPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &pol, nil
}

func GetPolicies(dir string) (map[string]*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	policies := make(map[string]*Policy)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		pol, err := GetPolicy(path)
		if err != nil {
			return nil, err
		}
		policies[entry.Name()] = pol
	}

	return policies, nil
}
