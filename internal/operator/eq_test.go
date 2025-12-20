package operator_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestEqOperator(t *testing.T) {
	tests := []struct {
		name     string
		node     *node.Node
		operands []any
		expected bool
	}{
		{
			name:     "equal integers",
			node:     node.New("x", 5),
			operands: []any{5},
			expected: true,
		},
		{
			name:     "not equal integers",
			node:     node.New("x", 5),
			operands: []any{6},
			expected: false,
		},
		{
			name:     "equal strings",
			node:     node.New("x", "rsa"),
			operands: []any{"rsa"},
			expected: true,
		},
		{
			name:     "nil node",
			node:     nil,
			operands: []any{5},
			expected: false,
		},
		{
			name:     "no operands",
			node:     node.New("x", 5),
			operands: []any{},
			expected: false,
		},
		{
			name:     "too many operands",
			node:     node.New("x", 5),
			operands: []any{5, 6},
			expected: false,
		},
	}

	op := operator.Eq{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := op.Evaluate(tt.node, tt.operands)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, ok)
			}
		})
	}
}
