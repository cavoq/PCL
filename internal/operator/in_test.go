package operator_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestInOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operands []any
		expected bool
	}{
		{"string in set", "SHA256WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, true},
		{"string not in set", "MD5WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, false},
		{"int in set", 2048, []any{2048, 4096}, true},
		{"int not in set", 1024, []any{2048, 4096}, false},
		{"single operand match", "RSA", []any{"RSA"}, true},
		{"numeric type coercion", 2048, []any{2048.0}, true},
	}

	op := operator.In{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, tt.operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInOperatorNilNode(t *testing.T) {
	op := operator.In{}
	got, _ := op.Evaluate(nil, nil, []any{"a"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestInOperatorNoOperands(t *testing.T) {
	op := operator.In{}
	n := node.New("test", "value")
	_, err := op.Evaluate(n, nil, []any{})
	if err == nil {
		t.Error("should error with no operands")
	}
}

func TestNotInOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operands []any
		expected bool
	}{
		{"string not in set", "MD5WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, true},
		{"string in set", "SHA256WithRSA", []any{"SHA256WithRSA", "SHA384WithRSA"}, false},
		{"int not in set", 1024, []any{2048, 4096}, true},
	}

	op := operator.NotIn{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, tt.operands)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}
