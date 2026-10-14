package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestLengthOperators(t *testing.T) {
	length := func(name string, op Operator, value any, bound int, want bool) evaluationCase {
		return evaluationCase{name: name, op: op, node: node.New("test", value), operands: []any{bound}, want: want}
	}
	children := tree("test", nil, node.New("a", 1), node.New("b", 2), node.New("c", 3))
	checkEvaluations(t, nil, []evaluationCase{
		length("max: string within limit", MaxLength{}, "hello", 10, true),
		length("max: string at limit", MaxLength{}, "hello", 5, true),
		length("max: string exceeds limit", MaxLength{}, "hello world", 5, false),
		length("max: empty string", MaxLength{}, "", 0, true),
		length("max: unicode string counts characters", MaxLength{}, "éé", 2, true),
		length("max: unicode string exceeds character limit", MaxLength{}, "éé", 1, false),
		length("max: bytes within limit", MaxLength{}, []byte{1, 2, 3}, 5, true),
		length("max: bytes exceeds limit", MaxLength{}, []byte{1, 2, 3, 4, 5, 6}, 5, false),
		length("max: slice within limit", MaxLength{}, []int{1, 2, 3}, 5, true),
		length("max: slice exceeds limit", MaxLength{}, []int{1, 2, 3, 4, 5, 6}, 5, false),
		{name: "max: children within limit", op: MaxLength{}, node: children, operands: []any{5}, want: true},
		{name: "max: children exceed limit", op: MaxLength{}, node: children, operands: []any{2}},
		{name: "max: nil node", op: MaxLength{}, operands: []any{10}},
		length("min: string meets minimum", MinLength{}, "hello", 3, true),
		length("min: string at minimum", MinLength{}, "hello", 5, true),
		length("min: string below minimum", MinLength{}, "hi", 5, false),
		length("min: empty string", MinLength{}, "", 0, true),
		length("min: unicode string counts characters", MinLength{}, "日本", 2, true),
		length("min: unicode string below character minimum", MinLength{}, "日本", 3, false),
		length("min: bytes meets minimum", MinLength{}, []byte{1, 2, 3}, 2, true),
		length("min: bytes below minimum", MinLength{}, []byte{1}, 5, false),
		{name: "min: nil node", op: MinLength{}, operands: []any{10}},
	})
}
