// Package policy provides policy file parsing and evaluation engine.
package policy

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/rule"
)

func ParseFile(path string) (Policy, error) {
	return parseFileWithIncludes(path, &includeState{
		active: make(map[string]bool),
		loaded: make(map[string]bool),
	})
}

func Parse(data []byte) (Policy, error) {
	var p Policy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parsing yaml: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Policy{}, fmt.Errorf("parsing yaml: multiple documents are not supported")
		}
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

type includeState struct {
	active map[string]bool
	loaded map[string]bool
}

func parseFileWithIncludes(path string, state *includeState) (Policy, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Policy{}, fmt.Errorf("resolving path: %w", err)
	}
	if state.active[absPath] {
		return Policy{}, fmt.Errorf("include cycle detected: %s", absPath)
	}
	if state.loaded[absPath] {
		return Policy{}, nil
	}
	state.active[absPath] = true
	defer delete(state.active, absPath)

	data, err := os.ReadFile(absPath)
	if err != nil {
		return Policy{}, fmt.Errorf("reading file: %w", err)
	}

	p, err := Parse(data)
	if err != nil {
		return Policy{}, err
	}

	if len(p.Includes) == 0 {
		state.loaded[absPath] = true
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
		incPolicy, err := parseFileWithIncludes(incPath, state)
		if err != nil {
			return Policy{}, fmt.Errorf("including %s: %w", inc, err)
		}
		merged.Rules = append(merged.Rules, incPolicy.Rules...)
	}

	merged.Rules = append(merged.Rules, p.Rules...)
	if err := validatePolicy(merged); err != nil {
		return Policy{}, fmt.Errorf("validating merged policy %s: %w", p.ID, err)
	}
	state.loaded[absPath] = true
	return merged, nil
}
