package operator_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestPresentOperator(t *testing.T) {
	tests := []struct {
		name     string
		node     *node.Node
		expected bool
	}{
		{
			name:     "node is present",
			node:     node.New("x", nil),
			expected: true,
		},
		{
			name:     "node is nil",
			node:     nil,
			expected: false,
		},
	}

	op := operator.Present{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, ok)
			}
		})
	}
}
