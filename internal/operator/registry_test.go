package operator

import (
	"errors"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

type testOp struct{}

func (testOp) Name() string { return "test" }

func (testOp) Evaluate(_ *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	return true, nil
}

type namedTestOp string

func (op namedTestOp) Name() string { return string(op) }

func (namedTestOp) Evaluate(_ *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
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

func TestRegistryValidate(t *testing.T) {
	wantErr := errors.New("invalid operands")
	validatorCalls := 0
	validator := OperandValidatorFunc(func(operands []any, registry *Registry) error {
		validatorCalls++
		if registry == nil {
			t.Fatal("validator did not receive registry")
		}
		if len(operands) != 1 || operands[0] != "invalid" {
			t.Fatalf("unexpected operands: %#v", operands)
		}
		return wantErr
	})

	reg := NewRegistry()
	reg.RegisterValidated(testOp{}, validator)
	err := reg.Validate("test", []any{"invalid"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Validate() error = %v, want wrapped %v", err, wantErr)
	}
	if validatorCalls != 1 {
		t.Fatalf("validator calls = %d, want 1", validatorCalls)
	}
}

func TestRegistryValidateAllowsOperatorWithoutValidator(t *testing.T) {
	reg := NewRegistry()
	reg.Register(testOp{})

	if err := reg.Validate("test", []any{"anything"}); err != nil {
		t.Fatalf("operator without validator was rejected: %v", err)
	}
}

func TestRegistryValidateRejectsUnknownOperator(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Validate("missing", nil); err == nil {
		t.Fatal("unknown operator passed validation")
	}
}

func TestRegistryRegisterReplacesExplicitValidator(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterValidated(testOp{}, OperandValidatorFunc(func([]any, *Registry) error {
		return errors.New("stale validator")
	}))
	reg.Register(testOp{})

	if err := reg.Validate("test", nil); err != nil {
		t.Fatalf("replacement retained stale validator: %v", err)
	}
}

func TestRegistryRegisterAttachesBuiltinValidatorByType(t *testing.T) {
	reg := NewRegistry()
	reg.Register(Eq{})

	if err := reg.Validate("eq", nil); err == nil {
		t.Fatal("manually registered built-in operator has no operand validator")
	}
}

func TestRegistryCustomOperatorDoesNotInheritBuiltinValidatorByName(t *testing.T) {
	reg := NewRegistry()
	reg.Register(Eq{})
	reg.Register(namedTestOp("eq"))

	if err := reg.Validate("eq", nil); err != nil {
		t.Fatalf("custom replacement inherited built-in validator: %v", err)
	}
}

type registryAwareTestOp struct {
	usedRegistry *Registry
}

func (op *registryAwareTestOp) Name() string { return "registryAware" }

func (op *registryAwareTestOp) Evaluate(_ *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	return false, nil
}

func (op *registryAwareTestOp) EvaluateWithRegistry(
	_ *node.Node,
	_ *EvaluationContext,
	_ []any,
	registry *Registry,
) (bool, error) {
	op.usedRegistry = registry
	return true, nil
}

func TestRegistryEvaluateUsesActiveRegistry(t *testing.T) {
	reg := NewRegistry()
	op := &registryAwareTestOp{}
	reg.Register(op)

	result, err := reg.Evaluate(op.Name(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Fatal("Evaluate() did not use registry-aware path")
	}
	if op.usedRegistry != reg {
		t.Fatal("registry-aware operator received a different registry")
	}
}

func TestRegistryEvaluateEnforcesOperandValidation(t *testing.T) {
	reg := NewRegistry()
	reg.Register(Eq{})

	if _, err := reg.Evaluate("eq", node.New("value", true), nil, nil); err == nil {
		t.Fatal("Evaluate accepted operands rejected by the registered contract")
	}
}
