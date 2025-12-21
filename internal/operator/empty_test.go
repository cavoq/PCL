package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *node.Node
		want  bool
	}{
		{
			name:  "nil node",
			setup: func() *node.Node { return nil },
			want:  true,
		},
		{
			name: "nil value no children",
			setup: func() *node.Node {
				return node.New("test", nil)
			},
			want: true,
		},
		{
			name: "empty string",
			setup: func() *node.Node {
				return node.New("test", "")
			},
			want: true,
		},
		{
			name: "non-empty string",
			setup: func() *node.Node {
				return node.New("test", "hello")
			},
			want: false,
		},
		{
			name: "empty bytes",
			setup: func() *node.Node {
				return node.New("test", []byte{})
			},
			want: true,
		},
		{
			name: "non-empty bytes",
			setup: func() *node.Node {
				return node.New("test", []byte{1, 2, 3})
			},
			want: false,
		},
		{
			name: "nil value with children",
			setup: func() *node.Node {
				n := node.New("test", nil)
				n.Children["child"] = node.New("child", "value")
				return n
			},
			want: false,
		},
		{
			name: "empty slice",
			setup: func() *node.Node {
				return node.New("test", []int{})
			},
			want: true,
		},
		{
			name: "non-empty slice",
			setup: func() *node.Node {
				return node.New("test", []int{1, 2, 3})
			},
			want: false,
		},
		{
			name: "non-empty primitive",
			setup: func() *node.Node {
				return node.New("test", 42)
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.setup()
			op := IsEmpty{}
			got, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("IsEmpty.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotEmpty(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *node.Node
		want  bool
	}{
		{
			name:  "nil node",
			setup: func() *node.Node { return nil },
			want:  false,
		},
		{
			name: "nil value no children",
			setup: func() *node.Node {
				return node.New("test", nil)
			},
			want: false,
		},
		{
			name: "empty string",
			setup: func() *node.Node {
				return node.New("test", "")
			},
			want: false,
		},
		{
			name: "non-empty string",
			setup: func() *node.Node {
				return node.New("test", "hello")
			},
			want: true,
		},
		{
			name: "nil value with children",
			setup: func() *node.Node {
				n := node.New("test", nil)
				n.Children["child"] = node.New("child", "value")
				return n
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.setup()
			op := NotEmpty{}
			got, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("NotEmpty.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsEmptyName(t *testing.T) {
	op := IsEmpty{}
	if op.Name() != "isEmpty" {
		t.Errorf("IsEmpty.Name() = %v, want isEmpty", op.Name())
	}
}

func TestNotEmptyName(t *testing.T) {
	op := NotEmpty{}
	if op.Name() != "notEmpty" {
		t.Errorf("NotEmpty.Name() = %v, want notEmpty", op.Name())
	}
}
