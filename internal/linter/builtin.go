package linter

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/policies"
)

// BuiltinPolicy is a policy pack shipped in the binary.
type BuiltinPolicy struct {
	ID   string
	File string
	Data []byte
	// Metadata is the pack's descriptive metadata, if any.
	Metadata policy.Metadata
}

// BuiltinPolicies returns the shipped policy packs ordered by id.
func BuiltinPolicies() ([]BuiltinPolicy, error) {
	files, err := fs.Glob(policies.FS, "*.yaml")
	if err != nil {
		return nil, err
	}
	builtins := make([]BuiltinPolicy, 0, len(files))
	for _, file := range files {
		data, err := policies.FS.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var header struct {
			ID       string          `yaml:"id"`
			Metadata policy.Metadata `yaml:"metadata"`
		}
		if err := yaml.Unmarshal(data, &header); err != nil {
			return nil, err
		}
		builtins = append(builtins, BuiltinPolicy{ID: header.ID, File: file, Data: data, Metadata: header.Metadata})
	}
	sort.Slice(builtins, func(i, j int) bool { return builtins[i].ID < builtins[j].ID })
	return builtins, nil
}

// LookupBuiltinPolicy returns the shipped pack that name refers to by id or
// file name, with or without .yaml, ignoring case.
func LookupBuiltinPolicy(name string) (BuiltinPolicy, bool) {
	builtins, err := BuiltinPolicies()
	if err != nil {
		return BuiltinPolicy{}, false
	}
	for _, builtin := range builtins {
		if strings.EqualFold(name, builtin.ID) || strings.EqualFold(name, builtin.File) ||
			strings.EqualFold(name, strings.TrimSuffix(builtin.File, ".yaml")) {
			return builtin, true
		}
	}
	return BuiltinPolicy{}, false
}

// BuiltinPolicyPrefix marks a --policy value that names a shipped pack.
const BuiltinPolicyPrefix = "builtin:"

// builtinPolicyReference reports whether a --policy value names a shipped
// pack: "builtin:<name>", or a bare name with no such file.
func builtinPolicyReference(path string) (BuiltinPolicy, bool) {
	if name, prefixed := strings.CutPrefix(path, BuiltinPolicyPrefix); prefixed {
		return LookupBuiltinPolicy(name)
	}
	if strings.ContainsRune(path, '/') || strings.ContainsRune(path, filepath.Separator) {
		return BuiltinPolicy{}, false
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		return BuiltinPolicy{}, false
	}
	return LookupBuiltinPolicy(path)
}

// resolvePolicyPath resolves a policy reference in a file in dir. A bare
// name of a shipped pack refers to it unless dir has such a file.
func resolvePolicyPath(dir, path string) string {
	if strings.HasPrefix(path, BuiltinPolicyPrefix) {
		return path
	}
	if !strings.ContainsRune(path, '/') && !strings.ContainsRune(path, filepath.Separator) {
		if _, err := os.Stat(filepath.Join(dir, path)); errors.Is(err, fs.ErrNotExist) {
			if builtin, ok := LookupBuiltinPolicy(path); ok {
				return BuiltinPolicyPrefix + builtin.ID
			}
		}
	}
	return resolvePath(dir, path)
}

func builtinPolicyIDs() string {
	builtins, err := BuiltinPolicies()
	if err != nil {
		return ""
	}
	ids := make([]string, 0, len(builtins))
	for _, builtin := range builtins {
		ids = append(ids, builtin.ID)
	}
	return strings.Join(ids, ", ")
}
