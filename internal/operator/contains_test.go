package operator_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestContainsOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operand  any
		expected bool
	}{
		{"slice contains string", []string{"digitalSignature", "keyEncipherment"}, "digitalSignature", true},
		{"slice does not contain", []string{"digitalSignature", "keyEncipherment"}, "cRLSign", false},
		{"slice contains int", []int{1, 2, 3}, 2, true},
		{"string contains substring", "SHA256WithRSA", "SHA256", true},
		{"string does not contain", "SHA256WithRSA", "MD5", false},
	}

	op := operator.Contains{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, []any{tt.operand})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestContainsWithChildren(t *testing.T) {
	parent := node.New("keyUsage", nil)
	parent.Children["0"] = node.New("0", "digitalSignature")
	parent.Children["1"] = node.New("1", "keyEncipherment")

	op := operator.Contains{}

	got, err := op.Evaluate(parent, nil, []any{"digitalSignature"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("should find digitalSignature in children")
	}

	got, err = op.Evaluate(parent, nil, []any{"cRLSign"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("should not find cRLSign in children")
	}
}

func TestContainsNilNode(t *testing.T) {
	op := operator.Contains{}
	got, _ := op.Evaluate(nil, nil, []any{"a"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestContainsWrongOperands(t *testing.T) {
	op := operator.Contains{}
	n := node.New("test", []string{"a"})

	_, err := op.Evaluate(n, nil, []any{})
	if err == nil {
		t.Error("should error with no operands")
	}

	_, err = op.Evaluate(n, nil, []any{"a", "b"})
	if err == nil {
		t.Error("should error with too many operands")
	}
}
