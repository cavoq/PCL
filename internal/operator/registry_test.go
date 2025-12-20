package operator_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/operator"
)

func TestRegistry(t *testing.T) {
	reg := operator.NewRegistry()

	eq := operator.Eq{}
	reg.Register(eq)

	op, err := reg.Get("eq")
	if err != nil {
		t.Fatalf("expected operator to be found")
	}

	if op.Name() != "eq" {
		t.Fatalf("expected eq operator, got %s", op.Name())
	}
}

func TestRegistryMissingOperator(t *testing.T) {
	reg := operator.NewRegistry()

	_, err := reg.Get("does_not_exist")
	if err == nil {
		t.Fatalf("expected error for missing operator")
	}
}
