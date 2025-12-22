package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestIsCritical(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *node.Node
		want  bool
	}{
		{
			name: "critical extension",
			setup: func() *node.Node {
				n := node.New("keyUsage", nil)
				n.Children["critical"] = node.New("critical", true)
				return n
			},
			want: true,
		},
		{
			name: "non-critical extension",
			setup: func() *node.Node {
				n := node.New("subjectKeyIdentifier", nil)
				n.Children["critical"] = node.New("critical", false)
				return n
			},
			want: false,
		},
		{
			name: "no critical field",
			setup: func() *node.Node {
				return node.New("extension", nil)
			},
			want: false,
		},
		{
			name:  "nil node",
			setup: func() *node.Node { return nil },
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.setup()
			op := IsCritical{}
			got, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("IsCritical.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotCritical(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *node.Node
		want  bool
	}{
		{
			name: "critical extension",
			setup: func() *node.Node {
				n := node.New("keyUsage", nil)
				n.Children["critical"] = node.New("critical", true)
				return n
			},
			want: false,
		},
		{
			name: "non-critical extension",
			setup: func() *node.Node {
				n := node.New("subjectKeyIdentifier", nil)
				n.Children["critical"] = node.New("critical", false)
				return n
			},
			want: true,
		},
		{
			name: "no critical field",
			setup: func() *node.Node {
				return node.New("extension", nil)
			},
			want: true,
		},
		{
			name:  "nil node",
			setup: func() *node.Node { return nil },
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := tt.setup()
			op := NotCritical{}
			got, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("NotCritical.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCriticalName(t *testing.T) {
	op := IsCritical{}
	if op.Name() != "isCritical" {
		t.Errorf("IsCritical.Name() = %v, want isCritical", op.Name())
	}
}

func TestNotCriticalName(t *testing.T) {
	op := NotCritical{}
	if op.Name() != "notCritical" {
		t.Errorf("NotCritical.Name() = %v, want notCritical", op.Name())
	}
}
