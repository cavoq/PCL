package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
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

	op := In{}
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
	op := In{}
	got, _ := op.Evaluate(nil, nil, []any{"a"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestInOperatorNoOperands(t *testing.T) {
	op := In{}
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

	op := NotIn{}
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

	op := Contains{}
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

	op := Contains{}

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
	op := Contains{}
	got, _ := op.Evaluate(nil, nil, []any{"a"})
	if got != false {
		t.Error("nil node should return false")
	}
}

func TestContainsWrongOperands(t *testing.T) {
	op := Contains{}
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
