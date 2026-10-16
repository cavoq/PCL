package operator

import (
	"math/big"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestNumericComparisons(t *testing.T) {
	compare := func(name string, op Operator, value, operand any, want bool) evaluationCase {
		return evaluationCase{name: name, op: op, node: node.New("test", value), operands: []any{operand}, want: want}
	}
	checkEvaluations(t, nil, []evaluationCase{
		compare("10 >= 5", Gte{}, 10, 5, true),
		compare("5 >= 5", Gte{}, 5, 5, true),
		compare("3 >= 5", Gte{}, 3, 5, false),
		compare("float 10.5 >= 10", Gte{}, 10.5, 10, true),
		compare("int vs float", Gte{}, 10, 10.0, true),
		compare("5 <= 10", Lte{}, 5, 10, true),
		compare("5 <= 5", Lte{}, 5, 5, true),
		compare("10 <= 5", Lte{}, 10, 5, false),
		compare("10 > 5", Gt{}, 10, 5, true),
		compare("5 > 5", Gt{}, 5, 5, false),
		compare("3 > 5", Gt{}, 3, 5, false),
		compare("5 < 10", Lt{}, 5, 10, true),
		compare("5 < 5", Lt{}, 5, 5, false),
		compare("10 < 5", Lt{}, 10, 5, false),
	})
}

func TestNumericComparisonPreservesLargeIntegerPrecision(t *testing.T) {
	const smaller = int64(9_007_199_254_740_992)
	larger := smaller + 1

	got, err := (Gt{}).Evaluate(node.New("large", larger), nil, []any{smaller})
	if err != nil {
		t.Fatalf("Gt returned error: %v", err)
	}
	if !got {
		t.Fatal("large integers were compared through a lossy float64 conversion")
	}

	got, err = (Lte{}).Evaluate(node.New("large", larger), nil, []any{float64(smaller)})
	if err != nil {
		t.Fatalf("Lte returned error: %v", err)
	}
	if got {
		t.Fatal("integer was treated as equal to a rounded float64 value")
	}
}

func TestCompareNilNode(t *testing.T) {
	ops := []Operator{Gte{}, Gt{}, Lte{}, Lt{}}
	for _, op := range ops {
		got, _ := op.Evaluate(nil, nil, []any{5})
		if got != false {
			t.Errorf("%s: nil node should return false", op.Name())
		}
	}
}

func TestCompareWrongOperands(t *testing.T) {
	n := node.New("test", 10)
	ops := []Operator{Gte{}, Gt{}, Lte{}, Lt{}}
	for _, op := range ops {
		_, err := op.Evaluate(n, nil, []any{})
		if err == nil {
			t.Errorf("%s: should error with no operands", op.Name())
		}
		_, err = op.Evaluate(n, nil, []any{1, 2})
		if err == nil {
			t.Errorf("%s: should error with too many operands", op.Name())
		}
	}
}

func TestPositive(t *testing.T) {
	positive := func(name string, value any, want bool) evaluationCase {
		return evaluationCase{name: name, op: Positive{}, node: node.New("test", value), want: want}
	}
	checkEvaluations(t, nil, []evaluationCase{
		positive("positive int", 42, true),
		positive("zero int", 0, false),
		positive("negative int", -5, false),
		positive("positive int64", int64(100), true),
		positive("zero int64", int64(0), false),
		positive("negative int64", int64(-100), false),
		positive("positive float64", 3.14, true),
		positive("zero float64", 0.0, false),
		positive("negative float64", -3.14, false),
		positive("positive big.Int", big.NewInt(999), true),
		positive("zero big.Int", big.NewInt(0), false),
		positive("negative big.Int", big.NewInt(-999), false),
		positive("positive string", "12345", true),
		positive("zero string", "0", false),
		positive("negative string", "-123", false),
		positive("invalid string", "abc", false),
		positive("nil value", nil, false),
		positive("unsupported type", struct{}{}, false),
		{name: "nil node", op: Positive{}},
	})
}

func TestOdd(t *testing.T) {
	odd := func(name string, value any, want bool) evaluationCase {
		return evaluationCase{name: name, op: Odd{}, node: node.New("test", value), want: want}
	}
	checkEvaluations(t, nil, []evaluationCase{
		odd("odd int", 3, true),
		odd("even int", 4, false),
		odd("negative odd int", -3, true),
		odd("odd int64", int64(7), true),
		odd("even uint64", uint64(8), false),
		odd("odd float64", 5.0, true),
		odd("odd big.Int", big.NewInt(9), true),
		odd("even big.Int", big.NewInt(10), false),
		odd("odd string", "12345", true),
		odd("even string", "1234", false),
		odd("invalid string", "abc", false),
		odd("nil value", nil, false),
		odd("unsupported type", struct{}{}, false),
		{name: "nil node", op: Odd{}},
	})
}

func TestMultipleOf(t *testing.T) {
	registry := DefaultRegistry()
	for _, test := range []struct {
		value any
		want  bool
	}{
		{2048, true}, {3072, true}, {2047, false}, {int64(4096), true}, {"4104", true}, {"4100", false}, {"x", false},
	} {
		got, err := registry.Evaluate("multipleOf", node.New("keySize", test.value), nil, []any{8})
		if err != nil || got != test.want {
			t.Errorf("multipleOf(%v, 8) = %v, %v; want %v", test.value, got, err, test.want)
		}
	}
	for _, operands := range [][]any{{0}, {-8}, {1.5}, {}, {8, 16}} {
		if err := registry.Validate("multipleOf", operands); err == nil {
			t.Errorf("Validate(%v) accepted invalid operands", operands)
		}
	}
}
