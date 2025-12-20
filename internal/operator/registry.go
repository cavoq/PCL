package operator

import "fmt"

type Registry struct {
	ops map[string]Operator
}

func NewRegistry() *Registry {
	return &Registry{ops: map[string]Operator{}}
}

func (r *Registry) Register(op Operator) {
	r.ops[op.Name()] = op
}

func (r *Registry) Get(name string) (Operator, error) {
	op, ok := r.ops[name]
	if !ok {
		return nil, fmt.Errorf("operator not found: %s", name)
	}
	return op, nil
}
