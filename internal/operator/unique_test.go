package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestUniquenessOperators(t *testing.T) {
	structured := func() map[string]any { return map[string]any{"key": []any{1, "two"}} }
	checkEvaluations(t, nil, []evaluationCase{
		{name: "values: nil node should return false", op: UniqueValues{}},
		{name: "values: node with no children should return true", op: UniqueValues{}, node: node.New("test", "value"), want: true},
		{name: "values: unique child values should return true", op: UniqueValues{},
			node: collection("test", "http://crl1.example.com", "http://crl2.example.com"), want: true},
		{name: "values: duplicate child values should return false", op: UniqueValues{},
			node: collection("test", "http://crl.example.com", "http://crl.example.com")},
		{name: "values: children with nil values should be skipped", op: UniqueValues{},
			node: collection("test", "http://crl.example.com", nil, "http://crl.example.com")},
		{name: "values: empty children should return true", op: UniqueValues{}, node: node.New("test", nil), want: true},
		{name: "values: duplicate structured values should return false", op: UniqueValues{},
			node: collection("test", structured(), structured())},

		{name: "children: nil node should return false", op: UniqueChildren{}},
		{name: "children: unique child string values should return true", op: UniqueChildren{},
			node: tree("test", nil, node.New("a", "value1"), node.New("b", "value2")), want: true},
		{name: "children: duplicate child string values should return false", op: UniqueChildren{},
			node: tree("test", nil, node.New("a", "same"), node.New("b", "same"))},
	})
}
