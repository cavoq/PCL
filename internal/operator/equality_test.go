package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
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

	op := Eq{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := op.Evaluate(tt.node, nil, tt.operands)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, ok)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	root := node.New("certificate", nil)
	root.Children["signatureAlgorithm"] = node.New("signatureAlgorithm", nil)
	root.Children["signatureAlgorithm"].Children["algorithm"] = node.New("algorithm", "SHA256-RSA")
	root.Children["tbsCertificate"] = node.New("tbsCertificate", nil)
	root.Children["tbsCertificate"].Children["signature"] = node.New("signature", "SHA256-RSA")

	ctx := &EvaluationContext{Root: root}

	tests := []struct {
		name     string
		node     *node.Node
		operands []any
		want     bool
	}{
		{
			name:     "matching values",
			node:     root.Children["tbsCertificate"].Children["signature"],
			operands: []any{"certificate.signatureAlgorithm.algorithm"},
			want:     true,
		},
		{
			name:     "non-matching values",
			node:     node.New("test", "SHA512-RSA"),
			operands: []any{"certificate.signatureAlgorithm.algorithm"},
			want:     false,
		},
		{
			name:     "nil node",
			node:     nil,
			operands: []any{"certificate.signatureAlgorithm.algorithm"},
			want:     false,
		},
		{
			name:     "missing operand",
			node:     root.Children["tbsCertificate"].Children["signature"],
			operands: []any{},
			want:     false,
		},
		{
			name:     "path not found",
			node:     root.Children["tbsCertificate"].Children["signature"],
			operands: []any{"certificate.nonexistent"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := Matches{}
			got, err := op.Evaluate(tt.node, ctx, tt.operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Matches.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesName(t *testing.T) {
	op := Matches{}
	if op.Name() != "matches" {
		t.Errorf("Matches.Name() = %v, want matches", op.Name())
	}
}
