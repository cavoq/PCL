package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestMaxLength(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		maxLen int
		want   bool
	}{
		{"string within limit", "hello", 10, true},
		{"string at limit", "hello", 5, true},
		{"string exceeds limit", "hello world", 5, false},
		{"empty string", "", 0, true},
		{"bytes within limit", []byte{1, 2, 3}, 5, true},
		{"bytes exceeds limit", []byte{1, 2, 3, 4, 5, 6}, 5, false},
		{"slice within limit", []int{1, 2, 3}, 5, true},
		{"slice exceeds limit", []int{1, 2, 3, 4, 5, 6}, 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			op := MaxLength{}
			got, err := op.Evaluate(n, nil, []any{tt.maxLen})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("MaxLength.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaxLengthWithChildren(t *testing.T) {
	n := node.New("test", nil)
	n.Children["a"] = node.New("a", 1)
	n.Children["b"] = node.New("b", 2)
	n.Children["c"] = node.New("c", 3)

	op := MaxLength{}
	got, err := op.Evaluate(n, nil, []any{5})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != true {
		t.Errorf("MaxLength.Evaluate() = %v, want true", got)
	}

	got, err = op.Evaluate(n, nil, []any{2})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Errorf("MaxLength.Evaluate() = %v, want false", got)
	}
}

func TestMinLength(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		minLen int
		want   bool
	}{
		{"string meets minimum", "hello", 3, true},
		{"string at minimum", "hello", 5, true},
		{"string below minimum", "hi", 5, false},
		{"empty string", "", 0, true},
		{"bytes meets minimum", []byte{1, 2, 3}, 2, true},
		{"bytes below minimum", []byte{1}, 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			op := MinLength{}
			got, err := op.Evaluate(n, nil, []any{tt.minLen})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("MinLength.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaxLengthNilNode(t *testing.T) {
	op := MaxLength{}
	got, _ := op.Evaluate(nil, nil, []any{10})
	if got != false {
		t.Errorf("MaxLength.Evaluate(nil) = %v, want false", got)
	}
}

func TestMinLengthNilNode(t *testing.T) {
	op := MinLength{}
	got, _ := op.Evaluate(nil, nil, []any{10})
	if got != false {
		t.Errorf("MinLength.Evaluate(nil) = %v, want false", got)
	}
}

func TestMaxLengthName(t *testing.T) {
	op := MaxLength{}
	if op.Name() != "maxLength" {
		t.Errorf("MaxLength.Name() = %v, want maxLength", op.Name())
	}
}

func TestMinLengthName(t *testing.T) {
	op := MinLength{}
	if op.Name() != "minLength" {
		t.Errorf("MinLength.Name() = %v, want minLength", op.Name())
	}
}
