package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestIsNull(t *testing.T) {
	tests := []struct {
		name     string
		node     *node.Node
		expected bool
	}{
		{
			name:     "nil node",
			node:     nil,
			expected: false,
		},
		{
			name: "parameters with null=true",
			node: &node.Node{
				Name:  "parameters",
				Value: nil,
				Children: map[string]*node.Node{
					"null": node.New("null", true),
				},
			},
			expected: true,
		},
		{
			name: "parameters with null=false",
			node: &node.Node{
				Name:  "parameters",
				Value: nil,
				Children: map[string]*node.Node{
					"null": node.New("null", false),
				},
			},
			expected: false,
		},
		{
			name: "parameters without null child",
			node: &node.Node{
				Name:     "parameters",
				Value:    nil,
				Children: map[string]*node.Node{},
			},
			expected: false,
		},
		{
			name: "parameters with non-bool null",
			node: &node.Node{
				Name:  "parameters",
				Value: nil,
				Children: map[string]*node.Node{
					"null": node.New("null", "true"),
				},
			},
			expected: false,
		},
	}

	op := IsNull{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}