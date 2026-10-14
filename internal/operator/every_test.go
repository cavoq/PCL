package operator

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

type everyCustomOperator struct{}

func (everyCustomOperator) Name() string { return "everyCustom" }

func (everyCustomOperator) Evaluate(
	n *node.Node,
	_ *EvaluationContext,
	operands []any,
) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}
	return n.Value == operands[0], nil
}

type everyFailingOperator struct{}

func (everyFailingOperator) Name() string { return "everyFailing" }

func (everyFailingOperator) Evaluate(
	_ *node.Node,
	_ *EvaluationContext,
	_ []any,
) (bool, error) {
	return false, fmt.Errorf("inner failure")
}

type everyRecordingOperator struct {
	seen *[]string
}

func (everyRecordingOperator) Name() string { return "everyRecording" }

func (operator everyRecordingOperator) Evaluate(
	n *node.Node,
	_ *EvaluationContext,
	_ []any,
) (bool, error) {
	*operator.seen = append(*operator.seen, n.Name)
	return true, nil
}

func TestEvery(t *testing.T) {
	// elements is a collection whose children hold child under its name.
	elements := func(children ...*node.Node) *node.Node {
		n := node.New("test", nil)
		for index, child := range children {
			key := strconv.Itoa(index)
			n.Children[key] = tree(key, nil, child)
		}
		return n
	}
	valueIn := func(path string, values ...any) []any {
		return []any{map[string]any{"path": path, "check": "in", "values": values}}
	}
	reasons := func(code int) *node.Node {
		return tree("extensions", nil, tree("2.5.29.21", nil, node.New("value", code)))
	}
	location := func(scheme string) *node.Node {
		return tree("accessLocation", nil, node.New("scheme", scheme))
	}
	twoElementsOneMissing := collection("test", nil, nil)
	twoElementsOneMissing.Children["0"].Children["value"] = node.New("value", 1)

	evaluate := func(name string, n *node.Node, operands []any, want, wantErr bool) evaluationCase {
		return evaluationCase{name: name, op: Every{}, node: n, operands: operands, want: want, wantErr: wantErr}
	}
	checkEvaluations(t, nil, []evaluationCase{
		evaluate("nil node returns false", nil, []any{map[string]any{"check": "present"}}, false, false),
		evaluate("empty children returns true", node.New("test", nil), []any{map[string]any{"check": "present"}}, true, false),
		evaluate("all children pass present check", collection("test", "value1", "value2"),
			[]any{map[string]any{"check": "present"}}, true, false),
		// A nil value is empty.
		evaluate("some children fail notEmpty check", collection("test", "value1", nil),
			[]any{map[string]any{"check": "notEmpty"}}, false, false),
		evaluate("all children pass in check with values", collection("test", 1, 3, 5),
			[]any{map[string]any{"check": "in", "values": []any{1, 3, 5, 7, 9}}}, true, false),
		evaluate("one child fails in check", collection("test", 1, 2, 5),
			[]any{map[string]any{"check": "in", "values": []any{1, 3, 5, 7, 9}}}, false, false),
		evaluate("sub-path check - all pass", elements(node.New("value", 1), node.New("value", 3)),
			valueIn("value", 1, 3, 5), true, false),
		evaluate("sub-path check - one fails", elements(node.New("value", 1), node.New("value", 2)),
			valueIn("value", 1, 3, 5), false, false),
		evaluate("sub-path missing - fails by default", twoElementsOneMissing,
			[]any{map[string]any{"path": "value", "check": "present"}}, false, false),
		evaluate("sub-path missing - skip with skipMissing", twoElementsOneMissing,
			[]any{map[string]any{"path": "value", "check": "present", "skipMissing": true}}, true, false),
		evaluate("nested sub-path check - simplified",
			elements(tree("a", nil, node.New("b", 1)), tree("a", nil, node.New("b", 3))),
			valueIn("a.b", 1, 3, 5, 9), true, false),
		evaluate("nested sub-path check", elements(reasons(1), reasons(3)),
			valueIn("extensions.2.5.29.21.value", 1, 3, 5, 9), true, false),
		evaluate("missing check operand returns error", node.New("test", nil), []any{map[string]any{"path": "value"}}, false, true),
		evaluate("unknown check operator returns error", node.New("test", nil),
			[]any{map[string]any{"check": "unknownOperator"}}, false, true),
		evaluate("no operands returns error", node.New("test", nil), []any{}, false, true),
		evaluate("new syntax - operator and operands", collection("test", 1, 3, 5),
			[]any{map[string]any{"operator": "in", "operands": []any{1, 3, 5, 7, 9}}}, true, false),
		evaluate("new syntax - wildcard path for AIA scheme",
			elements(location("http"), location("http")),
			[]any{map[string]any{"path": "*.accessLocation.scheme", "operator": "eq", "operands": []any{"http"}}}, true, false),
	})
}

func TestEveryValidatesStructuredOperands(t *testing.T) {
	checkOperandValidation(t, "every", []operandValidationCase{
		{
			name:     "modern form",
			operands: []any{map[string]any{"operator": "eq", "operands": []any{"value"}}},
		},
		{
			name:     "legacy form",
			operands: []any{map[string]any{"check": "in", "values": []any{1, 2}}},
		},
		{
			name:     "unknown field",
			operands: []any{map[string]any{"operator": "present", "typo": true}},
			wantErr:  true,
		},
		{
			name:     "conflicting operator aliases",
			operands: []any{map[string]any{"operator": "present", "check": "present"}},
			wantErr:  true,
		},
		{
			name:       "invalid nested operands",
			operands:   []any{map[string]any{"operator": "regex", "operands": []any{"["}}},
			wantErr:    true,
			wantDetail: "operands[0].operands",
		},
		{
			name:     "path whitespace",
			operands: []any{map[string]any{"path": " value", "operator": "present"}},
			wantErr:  true,
		},
	})
}

func TestEveryUsesActiveRegistryForNestedOperator(t *testing.T) {
	registry := NewRegistry()
	registry.Register(Every{})
	registry.RegisterValidated(
		everyCustomOperator{},
		OperandValidatorFunc(func(operands []any, _ *Registry) error {
			if len(operands) != 1 {
				return fmt.Errorf("requires one operand")
			}
			return nil
		}),
	)

	operands := []any{map[string]any{
		"operator": "everyCustom",
		"operands": []any{"match"},
	}}
	if err := registry.Validate("every", operands); err != nil {
		t.Fatalf("nested custom operator was not validated through active registry: %v", err)
	}

	target := node.New("items", nil)
	target.Children["0"] = node.New("0", "match")
	target.Children["1"] = node.New("1", "match")
	got, err := registry.Evaluate("every", target, nil, operands)
	if err != nil {
		t.Fatalf("nested custom operator evaluation failed: %v", err)
	}
	if !got {
		t.Fatal("nested custom operator did not evaluate through active registry")
	}
}

func TestEveryUsesCanonicalCollectionElements(t *testing.T) {
	tests := []struct {
		name string
		node *node.Node
		want []string
	}{
		{
			name: "numeric order ignores metadata and named aliases",
			node: func() *node.Node {
				collection := node.New("items", nil)
				one := node.New("one", 1)
				collection.Children["10"] = node.New("ten", 10)
				collection.Children["2"] = node.New("two", 2)
				collection.Children["1"] = one
				collection.Children["count"] = node.New("count", 3)
				collection.Children["first"] = one
				return collection
			}(),
			want: []string{"one", "two", "ten"},
		},
		{
			name: "named child fallback is ordered and deduplicates aliases",
			node: func() *node.Node {
				object := node.New("object", nil)
				alpha := node.New("alpha", "a")
				object.Children["zeta"] = node.New("zeta", "z")
				object.Children["alias"] = alpha
				object.Children["alpha"] = alpha
				return object
			}(),
			want: []string{"alpha", "zeta"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seen := []string{}
			registry := NewRegistry()
			registry.Register(Every{})
			registry.Register(everyRecordingOperator{seen: &seen})

			got, err := registry.Evaluate("every", test.node, nil, []any{map[string]any{
				"operator": "everyRecording",
			}})
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if !got {
				t.Fatal("Evaluate() = false, want true")
			}
			if fmt.Sprint(seen) != fmt.Sprint(test.want) {
				t.Fatalf("evaluation order = %v, want %v", seen, test.want)
			}
		})
	}
}

func TestEveryWildcardUsesCanonicalCollectionElements(t *testing.T) {
	outer := node.New("outer", nil)
	inner := node.New("inner", nil)
	zero := node.New("zero", 0)
	inner.Children["2"] = node.New("two", 2)
	inner.Children["0"] = zero
	inner.Children["count"] = node.New("count", 2)
	inner.Children["first"] = zero
	outer.Children["0"] = inner

	seen := []string{}
	registry := NewRegistry()
	registry.Register(Every{})
	registry.Register(everyRecordingOperator{seen: &seen})
	got, err := registry.Evaluate("every", outer, nil, []any{map[string]any{
		"path":     "*",
		"operator": "everyRecording",
	}})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !got {
		t.Fatal("Evaluate() = false, want true")
	}
	if want := []string{"zero", "two"}; fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("wildcard evaluation order = %v, want %v", seen, want)
	}
}

func TestEveryWildcardHonorsSkipMissing(t *testing.T) {
	target := node.New("outer", nil)
	branches := node.New("branches", nil)
	withValue := node.New("withValue", nil)
	withValue.Children["value"] = node.New("value", "match")
	branches.Children["0"] = withValue
	branches.Children["1"] = node.New("withoutValue", nil)
	target.Children["0"] = branches

	for _, test := range []struct {
		name        string
		skipMissing bool
		want        bool
	}{
		{name: "missing wildcard branch fails by default", want: false},
		{name: "missing wildcard branch can be skipped", skipMissing: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Every{}.Evaluate(target, nil, []any{map[string]any{
				"path":        "*.value",
				"operator":    "eq",
				"operands":    []any{"match"},
				"skipMissing": test.skipMissing,
			}})
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("Evaluate() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEveryWrapsNestedEvaluationError(t *testing.T) {
	registry := NewRegistry()
	registry.Register(Every{})
	registry.Register(everyFailingOperator{})

	target := node.New("items", nil)
	target.Children["entry"] = node.New("entry", "value")
	_, err := registry.Evaluate("every", target, nil, []any{map[string]any{
		"operator": "everyFailing",
	}})
	if err == nil {
		t.Fatal("expected nested evaluation error")
	}
	for _, want := range []string{`inner operator "everyFailing"`, `child "entry"`, "inner failure"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("nested error %q does not contain %q", err, want)
		}
	}
}
