package operator

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

// tree is a node holding value whose children are keyed by their names.
func tree(name string, value any, children ...*node.Node) *node.Node {
	n := node.New(name, value)
	for _, child := range children {
		n.Children[child.Name] = child
	}
	return n
}

// collection is a node whose children "0", "1", ... hold values.
func collection(name string, values ...any) *node.Node {
	n := node.New(name, nil)
	for index, value := range values {
		key := strconv.Itoa(index)
		n.Children[key] = node.New(key, value)
	}
	return n
}

// operandValidationCase is a set of operands and whether the default
// registry rejects them, with a text the error must contain.
type operandValidationCase struct {
	name       string
	operands   []any
	wantErr    bool
	wantDetail string
}

func checkOperandValidation(t *testing.T, operator string, tests []operandValidationCase) {
	t.Helper()
	registry := DefaultRegistry()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := registry.Validate(operator, test.operands)
			if test.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
			if test.wantDetail != "" && (err == nil || !strings.Contains(err.Error(), test.wantDetail)) {
				t.Fatalf("validation error %q does not contain %q", err, test.wantDetail)
			}
		})
	}
}

// evaluationCase is an operator evaluation and its expected result.
type evaluationCase struct {
	name     string
	op       Operator
	node     *node.Node
	operands []any
	want     bool
	wantErr  bool
}

func checkEvaluations(t *testing.T, ctx *EvaluationContext, tests []evaluationCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.op.Evaluate(tt.node, ctx, tt.operands)
			if (err != nil) != tt.wantErr {
				t.Fatalf("%s error = %v, want error %v", tt.op.Name(), err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("%s = %v, want %v", tt.op.Name(), got, tt.want)
			}
		})
	}
}
