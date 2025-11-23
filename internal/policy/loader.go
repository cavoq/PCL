package policy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		fmt.Printf("Error closing file: %v\n", err)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	pol := &Policy{}
	if err := yaml.Unmarshal(data, pol); err != nil {
		return nil, err
	}

	return pol, nil
}

func LoadPolicies(dir string) (map[string]*Policy, error) {
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
		pol, err := LoadPolicy(path)
		if err != nil {
			return nil, err
		}
		policies[entry.Name()] = pol
	}

	return policies, nil
}
