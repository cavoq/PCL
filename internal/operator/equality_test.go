package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestEqOperator(t *testing.T) {
	checkEvaluations(t, nil, []evaluationCase{
		{name: "equal integers", op: Eq{}, node: node.New("x", 5), operands: []any{5}, want: true},
		{name: "not equal integers", op: Eq{}, node: node.New("x", 5), operands: []any{6}},
		{name: "equal strings", op: Eq{}, node: node.New("x", "rsa"), operands: []any{"rsa"}, want: true},
		{name: "nil node", op: Eq{}, operands: []any{5}},
		{name: "nil node is not implicit false", op: Eq{}, operands: []any{false}},
		{name: "no operands", op: Eq{}, node: node.New("x", 5), operands: []any{}},
		{name: "too many operands", op: Eq{}, node: node.New("x", 5), operands: []any{5, 6}},
	})
}

func TestNeqOperator(t *testing.T) {
	checkEvaluations(t, nil, []evaluationCase{
		{name: "different integers", op: Neq{}, node: node.New("x", 5), operands: []any{6}, want: true},
		{name: "equal integers", op: Neq{}, node: node.New("x", 5), operands: []any{5}},
		{name: "equal booleans", op: Neq{}, node: node.New("x", true), operands: []any{true}},
		{name: "nil node is not equal", op: Neq{}, operands: []any{true}, want: true},
		{name: "no operands", op: Neq{}, node: node.New("x", 5), operands: []any{}},
		{name: "nil node without operands", op: Neq{}, operands: []any{}},
	})
}

func TestMatches(t *testing.T) {
	signature := node.New("signature", "SHA256-RSA")
	root := tree("certificate", nil,
		tree("signatureAlgorithm", nil, node.New("algorithm", "SHA256-RSA")),
		tree("tbsCertificate", nil, signature))
	algorithm := []any{"certificate.signatureAlgorithm.algorithm"}

	checkEvaluations(t, &EvaluationContext{Root: root}, []evaluationCase{
		{name: "matching values", op: Matches{}, node: signature, operands: algorithm, want: true},
		{name: "non-matching values", op: Matches{}, node: node.New("test", "SHA512-RSA"), operands: algorithm},
		{name: "nil node", op: Matches{}, operands: algorithm},
		{name: "missing operand", op: Matches{}, node: signature, operands: []any{}},
		{name: "path not found", op: Matches{}, node: signature, operands: []any{"certificate.nonexistent"}},
	})
}
