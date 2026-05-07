package operator

import (
	"bytes"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestUTF8NoBOM(t *testing.T) {
	op := UTF8NoBOM{}

	// UTF-8 BOM byte sequence: EF BB BF
	utf8BOM := make([]byte, 0, 17)
	utf8BOM = append(utf8BOM, 0xEF, 0xBB, 0xBF)

	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{
			name:     "string without BOM",
			value:    "normal UTF-8 string",
			expected: true,
		},
		{
			name:     "string with BOM",
			value:    string(utf8BOM) + "string with BOM",
			expected: false,
		},
		{
			name:     "bytes without BOM",
			value:    []byte("normal bytes"),
			expected: true,
		},
		{
			name:     "bytes with BOM",
			value:    append(utf8BOM, []byte("bytes with BOM")...),
			expected: false,
		},
		{
			name:     "empty string",
			value:    "",
			expected: true,
		},
		{
			name:     "empty bytes",
			value:    []byte{},
			expected: true,
		},
		{
			name:     "non-string value",
			value:    123,
			expected: true, // non-string/bytes cannot have BOM
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			result, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestContainsBOM(t *testing.T) {
	op := ContainsBOM{}

	utf8BOM := []byte{0xEF, 0xBB, 0xBF}

	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{
			name:     "string without BOM",
			value:    "normal string",
			expected: false,
		},
		{
			name:     "string with BOM",
			value:    string(utf8BOM) + "string with BOM",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			result, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Test that utf8NoBom can be used with actual UTF-8 strings
func TestUTF8NoBOMWithMultibyteChars(t *testing.T) {
	op := UTF8NoBOM{}

	// Chinese characters (multi-byte UTF-8)
	chineseStr := "医者@example.com"
	n := node.New("test", chineseStr)
	result, err := op.Evaluate(n, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !result {
		t.Errorf("multi-byte UTF-8 string should pass utf8NoBom check")
	}

	// Japanese characters
	japaneseStr := "テスト"
	n2 := node.New("test", japaneseStr)
	result2, err := op.Evaluate(n2, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !result2 {
		t.Errorf("Japanese UTF-8 string should pass utf8NoBom check")
	}

	// Verify BOM detection works with raw bytes
	utf8BOM := bytes.Join([][]byte{{0xEF, 0xBB, 0xBF}, []byte("医者@example.com")}, nil)
	n3 := node.New("test", utf8BOM)
	result3, err := op.Evaluate(n3, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result3 {
		t.Errorf("bytes with BOM should fail utf8NoBom check")
	}
}