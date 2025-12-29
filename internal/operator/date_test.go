package operator

import (
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/node"
)

func TestBeforeOperator(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	ctx := &EvaluationContext{Now: now}

	tests := []struct {
		name     string
		value    time.Time
		expected bool
	}{
		{"past is before now", past, true},
		{"future is not before now", future, false},
	}

	op := Before{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, ctx, []any{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAfterOperator(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	ctx := &EvaluationContext{Now: now}

	tests := []struct {
		name     string
		value    time.Time
		expected bool
	}{
		{"future is after now", future, true},
		{"past is not after now", past, false},
	}

	op := After{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node.New("test", tt.value)
			got, err := op.Evaluate(n, ctx, []any{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBeforeWithExplicitNow(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)

	ctx := &EvaluationContext{Now: now}

	op := Before{}
	n := node.New("test", past)
	got, err := op.Evaluate(n, ctx, []any{"now"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Error("past should be before now")
	}
}

func TestDateOperatorNilNode(t *testing.T) {
	ops := []Operator{Before{}, After{}}
	for _, op := range ops {
		got, _ := op.Evaluate(nil, nil, []any{})
		if got != false {
			t.Errorf("%s: nil node should return false", op.Name())
		}
	}
}
