package operator

import (
	"math/big"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

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
