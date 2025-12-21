package operator

import (
	"math/big"
	"testing"

	"github.com/cavoq/PCL/internal/node"
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

	op := Gte{}
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

	op := Lte{}
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

	op := Gt{}
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

	op := Lt{}
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
	ops := []Operator{Gte{}, Gt{}, Lte{}, Lt{}}
	for _, op := range ops {
		got, _ := op.Evaluate(nil, nil, []any{5})
		if got != false {
			t.Errorf("%s: nil node should return false", op.Name())
		}
	}
}

func TestCompareWrongOperands(t *testing.T) {
	n := node.New("test", 10)
	ops := []Operator{Gte{}, Gt{}, Lte{}, Lt{}}
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

func TestPositive(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"positive int", 42, true},
		{"zero int", 0, false},
		{"negative int", -5, false},
		{"positive int64", int64(100), true},
		{"zero int64", int64(0), false},
		{"negative int64", int64(-100), false},
		{"positive float64", 3.14, true},
		{"zero float64", 0.0, false},
		{"negative float64", -3.14, false},
		{"positive big.Int", big.NewInt(999), true},
		{"zero big.Int", big.NewInt(0), false},
		{"negative big.Int", big.NewInt(-999), false},
		{"positive string", "12345", true},
		{"zero string", "0", false},
		{"negative string", "-123", false},
		{"invalid string", "abc", false},
		{"nil value", nil, false},
		{"unsupported type", struct{}{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			op := Positive{}
			got, err := op.Evaluate(n, nil, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Positive.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPositiveNilNode(t *testing.T) {
	op := Positive{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != false {
		t.Errorf("Positive.Evaluate(nil) = %v, want false", got)
	}
}

func TestPositiveName(t *testing.T) {
	op := Positive{}
	if op.Name() != "positive" {
		t.Errorf("Positive.Name() = %v, want positive", op.Name())
	}
}
