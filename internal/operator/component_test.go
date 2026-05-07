package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestComponentMaxLength(t *testing.T) {
	op := ComponentMaxLength{}

	tests := []struct {
		name     string
		value    string
		maxLen   int
		delimiter string
		expected bool
	}{
		{
			name:     "valid DNS labels (all under 63)",
			value:    "subdomain.example.test",
			maxLen:   63,
			delimiter: ".",
			expected: true,
		},
		{
			name:     "label exceeds max 63",
			value:    "thisisaverylonglabelthatdefinitelyexceedssixtythreecharactersaaa.example.test",
			maxLen:   63,
			delimiter: ".",
			expected: false,
		},
		{
			name:     "exactly max length 63",
			value:    "exactly63characterssssssssssssssssssssssssssssssssssss.example",
			maxLen:   63,
			delimiter: ".",
			expected: true,
		},
		{
			name:     "single component valid",
			value:    "short",
			maxLen:   63,
			delimiter: ".",
			expected: true,
		},
		{
			name:     "empty component should pass maxLength (length 0 <= any max)",
			value:    "example..test",
			maxLen:   63,
			delimiter: ".",
			expected: true,
		},
		{
			name:     "custom delimiter slash",
			value:    "path/to/resource",
			maxLen:   10,
			delimiter: "/",
			expected: true,
		},
		{
			name:     "custom delimiter exceeds",
			value:    "verylongpathsegment/to/resource",
			maxLen:   10,
			delimiter: "/",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			operands := []any{tt.maxLen, tt.delimiter}
			result, err := op.Evaluate(n, nil, operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}

	// Test with default delimiter
	t.Run("default delimiter", func(t *testing.T) {
		n := node.New("test", "subdomain.example.test")
		result, err := op.Evaluate(n, nil, []any{63})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !result {
			t.Errorf("expected true for valid DNS with default delimiter")
		}
	})
}

func TestComponentMinLength(t *testing.T) {
	op := ComponentMinLength{}

	tests := []struct {
		name     string
		value    string
		minLen   int
		delimiter string
		expected bool
	}{
		{
			name:     "all labels meet minimum",
			value:    "subdomain.example.test",
			minLen:   1,
			delimiter: ".",
			expected: true,
		},
		{
			name:     "empty label fails minimum",
			value:    "example..test",
			minLen:   1,
			delimiter: ".",
			expected: false,
		},
		{
			name:     "single char labels",
			value:    "a.b.c",
			minLen:   1,
			delimiter: ".",
			expected: true,
		},
		{
			name:     "label too short",
			value:    "ab.c.d",
			minLen:   3,
			delimiter: ".",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			operands := []any{tt.minLen, tt.delimiter}
			result, err := op.Evaluate(n, nil, operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComponentRegex(t *testing.T) {
	op := ComponentRegex{}

	tests := []struct {
		name     string
		value    string
		pattern  string
		delimiter string
		expected bool
	}{
		{
			name:     "valid DNS labels (alphanumeric and hyphen)",
			value:    "sub-domain.example.test",
			pattern:  "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
			delimiter: ".",
			expected: true,
		},
		{
			name:     "DNS label with underscore fails",
			value:    "invalid_label.example.test",
			pattern:  "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
			delimiter: ".",
			expected: false,
		},
		{
			name:     "IDN A-label format",
			value:    "xn--pss25c.xn--abc.example",
			pattern:  "^(xn--[a-z0-9-]+|[a-z0-9]([a-z0-9-]*[a-z0-9])?)$",
			delimiter: ".",
			expected: true,
		},
		{
			name:     "label starts with hyphen fails",
			value:    "-invalid.example.test",
			pattern:  "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
			delimiter: ".",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			operands := []any{tt.pattern, tt.delimiter}
			result, err := op.Evaluate(n, nil, operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComponentNotRegex(t *testing.T) {
	op := ComponentNotRegex{}

	tests := []struct {
		name     string
		value    string
		pattern  string
		delimiter string
		expected bool
	}{
		{
			name:     "no underscore in labels",
			value:    "valid.example.test",
			pattern:  "_",
			delimiter: ".",
			expected: true,
		},
		{
			name:     "underscore present fails",
			value:    "invalid_label.example.test",
			pattern:  "_",
			delimiter: ".",
			expected: false,
		},
		{
			name:     "no forbidden chars",
			value:    "clean.example",
			pattern:  "[*?]",
			delimiter: ".",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			operands := []any{tt.pattern, tt.delimiter}
			result, err := op.Evaluate(n, nil, operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}