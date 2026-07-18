package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
)

type Registry struct {
	ops        map[string]Operator
	validators map[string]OperandValidator
}

func NewRegistry() *Registry {
	return &Registry{
		ops:        map[string]Operator{},
		validators: map[string]OperandValidator{},
	}
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.RegisterAll(All)
	return r
}

func (r *Registry) Register(op Operator) {
	name := op.Name()
	r.ops[name] = op
	delete(r.validators, name)
	if validator, ok := op.(OperandValidator); ok {
		r.validators[name] = validator
	} else if validator, ok := builtinOperandValidator(op); ok {
		r.validators[name] = validator
	}
}

// RegisterValidated registers an operator with an explicit operand validator.
// The validator may be shared by many operator types. Passing nil retains an
// OperandValidator implemented by the operator itself, if present.
func (r *Registry) RegisterValidated(op Operator, validator OperandValidator) {
	r.Register(op)
	if validator != nil {
		r.validators[op.Name()] = validator
	}
}

func (r *Registry) RegisterAll(ops []Operator) {
	for _, op := range ops {
		r.Register(op)
	}
}

func (r *Registry) Get(name string) (Operator, error) {
	op, ok := r.ops[name]
	if !ok {
		return nil, fmt.Errorf("operator not found: %s", name)
	}
	return op, nil
}

// Validate verifies an operator invocation using the operator's optional
// operand validation capability. Registered operators without a validator are
// accepted for backwards compatibility.
func (r *Registry) Validate(name string, operands []any) error {
	if _, ok := r.ops[name]; !ok {
		return fmt.Errorf("unknown operator %q", name)
	}

	validator, ok := r.validators[name]
	if !ok {
		return nil
	}
	if err := validator.ValidateOperands(operands, r); err != nil {
		return fmt.Errorf("operator %q: %w", name, err)
	}
	return nil
}

// Evaluate validates and invokes an operator using this registry. Composite
// operators can opt into RegistryAwareOperator to reuse the same registry for
// nested calls.
func (r *Registry) Evaluate(
	name string,
	n *node.Node,
	ctx *EvaluationContext,
	operands []any,
) (bool, error) {
	if err := r.Validate(name, operands); err != nil {
		return false, err
	}
	return r.evaluateValidated(name, n, ctx, operands)
}

// evaluateValidated invokes an operator after its invocation has already been
// validated. Composite operators use it for repeated inner evaluations so a
// single nested contract is not revalidated for every child.
func (r *Registry) evaluateValidated(
	name string,
	n *node.Node,
	ctx *EvaluationContext,
	operands []any,
) (bool, error) {
	op, err := r.Get(name)
	if err != nil {
		return false, err
	}

	if registryAware, ok := op.(RegistryAwareOperator); ok {
		return registryAware.EvaluateWithRegistry(n, ctx, operands, r)
	}
	return op.Evaluate(n, ctx, operands)
}
