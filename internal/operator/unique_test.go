package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestUniqueValues(t *testing.T) {
	op := UniqueValues{}

	tests := []struct {
		name     string
		node     *node.Node
		want     bool
	}{
		{
			name: "nil node should return false",
			node: nil,
			want: false,
		},
		{
			name: "node with no children should return true",
			node: node.New("test", "value"),
			want: true,
		},
		{
			name: "unique child values should return true",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "http://crl1.example.com")
				n.Children["1"] = node.New("1", "http://crl2.example.com")
				return n
			}(),
			want: true,
		},
		{
			name: "duplicate child values should return false",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "http://crl.example.com")
				n.Children["1"] = node.New("1", "http://crl.example.com")
				return n
			}(),
			want: false,
		},
		{
			name: "children with nil values should be skipped",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "http://crl.example.com")
				n.Children["1"] = node.New("1", nil)
				n.Children["2"] = node.New("2", "http://crl.example.com")
				return n
			}(),
			want: false,
		},
		{
			name: "empty children should return true",
			node: node.New("test", nil),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("UniqueValues.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("UniqueValues.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUniqueChildren(t *testing.T) {
	op := UniqueChildren{}

	tests := []struct {
		name     string
		node     *node.Node
		want     bool
	}{
		{
			name: "nil node should return false",
			node: nil,
			want: false,
		},
		{
			name: "unique child string values should return true",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["a"] = node.New("a", "value1")
				n.Children["b"] = node.New("b", "value2")
				return n
			}(),
			want: true,
		},
		{
			name: "duplicate child string values should return false",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["a"] = node.New("a", "same")
				n.Children["b"] = node.New("b", "same")
				return n
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("UniqueChildren.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("UniqueChildren.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}