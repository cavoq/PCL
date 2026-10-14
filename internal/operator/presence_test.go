package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestPresenceOperators(t *testing.T) {
	withChild := tree("test", nil, node.New("child", "value"))
	checkEvaluations(t, nil, []evaluationCase{
		{name: "present: node is present", op: Present{}, node: node.New("x", nil), want: true},
		{name: "present: node is nil", op: Present{}},

		{name: "isEmpty: nil node", op: IsEmpty{}, want: true},
		{name: "isEmpty: nil value no children", op: IsEmpty{}, node: node.New("test", nil), want: true},
		{name: "isEmpty: empty string", op: IsEmpty{}, node: node.New("test", ""), want: true},
		{name: "isEmpty: non-empty string", op: IsEmpty{}, node: node.New("test", "hello")},
		{name: "isEmpty: empty bytes", op: IsEmpty{}, node: node.New("test", []byte{}), want: true},
		{name: "isEmpty: non-empty bytes", op: IsEmpty{}, node: node.New("test", []byte{1, 2, 3})},
		{name: "isEmpty: nil value with children", op: IsEmpty{}, node: withChild},
		{name: "isEmpty: empty slice", op: IsEmpty{}, node: node.New("test", []int{}), want: true},
		{name: "isEmpty: non-empty slice", op: IsEmpty{}, node: node.New("test", []int{1, 2, 3})},
		{name: "isEmpty: non-empty primitive", op: IsEmpty{}, node: node.New("test", 42)},

		{name: "notEmpty: nil node", op: NotEmpty{}},
		{name: "notEmpty: nil value no children", op: NotEmpty{}, node: node.New("test", nil)},
		{name: "notEmpty: empty string", op: NotEmpty{}, node: node.New("test", "")},
		{name: "notEmpty: non-empty string", op: NotEmpty{}, node: node.New("test", "hello"), want: true},
		{name: "notEmpty: nil value with children", op: NotEmpty{}, node: withChild, want: true},
	})
}
