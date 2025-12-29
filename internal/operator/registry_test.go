package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

type testOp struct{}

func (testOp) Name() string { return "test" }

func (testOp) Evaluate(_ *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	return true, nil
}

func TestRegistryGetUnknown(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Get("missing")
	if err == nil {
		t.Fatalf("expected error for missing operator")
	}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	reg.Register(testOp{})

	op, err := reg.Get("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if op.Name() != "test" {
		t.Fatalf("unexpected operator name: %s", op.Name())
	}
}
