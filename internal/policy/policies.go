package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

const DefaultCertOrder = 1000

func getCertOrder(order *int) int {
	if order != nil {
		return *order
	}
	return DefaultCertOrder
}

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

func GetPolicyChain(path string) (*PolicyChain, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	chain := &PolicyChain{
		Name: filepath.Base(path),
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			polPath := filepath.Join(path, entry.Name())
			pol, err := GetPolicy(polPath)
			if err != nil {
				return nil, err
			}
			chain.Policies = append(chain.Policies, pol)
		}

		OrderPolicies(chain.Policies)

	} else {
		pol, err := GetPolicy(path)
		if err != nil {
			return nil, err
		}
		chain.Policies = []*Policy{pol}
	}

	return chain, nil
}

func OrderPolicies(policies []*Policy) {
	slices.SortFunc(policies, func(a, b *Policy) int {
		return getCertOrder(a.CertOrder) - getCertOrder(b.CertOrder)
	})
}
