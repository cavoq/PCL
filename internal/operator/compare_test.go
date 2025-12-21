package operator_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

func TestGteOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operand  any
		expected bool
		wantErr  bool
	}{
		{"10 >= 5", 10, 5, true, false},
		{"5 >= 5", 5, 5, true, false},
		{"3 >= 5", 3, 5, false, false},
		{"float 10.5 >= 10", 10.5, 10, true, false},
		{"int vs float", 10, 10.0, true, false},
	}

	op := operator.Gte{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, nil, []any{tt.operand})
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLteOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operand  any
		expected bool
	}{
		{"5 <= 10", 5, 10, true},
		{"5 <= 5", 5, 5, true},
		{"10 <= 5", 10, 5, false},
	}

	op := operator.Lte{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, _ := op.Evaluate(n, nil, []any{tt.operand})
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGtOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operand  any
		expected bool
	}{
		{"10 > 5", 10, 5, true},
		{"5 > 5", 5, 5, false},
		{"3 > 5", 3, 5, false},
	}

	op := operator.Gt{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, _ := op.Evaluate(n, nil, []any{tt.operand})
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLtOperator(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		operand  any
		expected bool
	}{
		{"5 < 10", 5, 10, true},
		{"5 < 5", 5, 5, false},
		{"10 < 5", 10, 5, false},
	}

	op := operator.Lt{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, _ := op.Evaluate(n, nil, []any{tt.operand})
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCompareNilNode(t *testing.T) {
	ops := []operator.Operator{operator.Gte{}, operator.Gt{}, operator.Lte{}, operator.Lt{}}
	for _, op := range ops {
		got, _ := op.Evaluate(nil, nil, []any{5})
		if got != false {
			t.Errorf("%s: nil node should return false", op.Name())
		}
	}
}

func TestCompareWrongOperands(t *testing.T) {
	n := node.New("test", 10)
	ops := []operator.Operator{operator.Gte{}, operator.Gt{}, operator.Lte{}, operator.Lt{}}
	for _, op := range ops {
		_, err := op.Evaluate(n, nil, []any{})
		if err == nil {
			t.Errorf("%s: should error with no operands", op.Name())
		}
		_, err = op.Evaluate(n, nil, []any{1, 2})
		if err == nil {
			t.Errorf("%s: should error with too many operands", op.Name())
		}
	}
}
