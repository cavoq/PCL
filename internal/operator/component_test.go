package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestComponentOperators(t *testing.T) {
	const dnsLabel = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
	tests := []struct {
		name     string
		op       Operator
		value    string
		operands []any
		want     bool
	}{
		{"max length: valid DNS labels (all under 63)", ComponentMaxLength{}, "subdomain.example.test", []any{63, "."}, true},
		{"max length: label exceeds max 63", ComponentMaxLength{},
			"thisisaverylonglabelthatdefinitelyexceedssixtythreecharactersaaa.example.test", []any{63, "."}, false},
		{"max length: exactly max length 63", ComponentMaxLength{},
			"exactly63characterssssssssssssssssssssssssssssssssssss.example", []any{63, "."}, true},
		{"max length: single component valid", ComponentMaxLength{}, "short", []any{63, "."}, true},
		{"max length: empty component passes (length 0 <= any max)", ComponentMaxLength{}, "example..test", []any{63, "."}, true},
		{"max length: custom delimiter slash", ComponentMaxLength{}, "path/to/resource", []any{10, "/"}, true},
		{"max length: custom delimiter exceeds", ComponentMaxLength{}, "verylongpathsegment/to/resource", []any{10, "/"}, false},
		{"max length: default delimiter", ComponentMaxLength{}, "subdomain.example.test", []any{63}, true},
		{"min length: all labels meet minimum", ComponentMinLength{}, "subdomain.example.test", []any{1, "."}, true},
		{"min length: empty label fails minimum", ComponentMinLength{}, "example..test", []any{1, "."}, false},
		{"min length: single char labels", ComponentMinLength{}, "a.b.c", []any{1, "."}, true},
		{"min length: label too short", ComponentMinLength{}, "ab.c.d", []any{3, "."}, false},
		{"regex: valid DNS labels (alphanumeric and hyphen)", ComponentRegex{}, "sub-domain.example.test", []any{dnsLabel, "."}, true},
		{"regex: DNS label with underscore fails", ComponentRegex{}, "invalid_label.example.test", []any{dnsLabel, "."}, false},
		{"regex: IDN A-label format", ComponentRegex{}, "xn--pss25c.xn--abc.example",
			[]any{"^(xn--[a-z0-9-]+|[a-z0-9]([a-z0-9-]*[a-z0-9])?)$", "."}, true},
		{"regex: label starts with hyphen fails", ComponentRegex{}, "-invalid.example.test", []any{dnsLabel, "."}, false},
		{"not regex: no underscore in labels", ComponentNotRegex{}, "valid.example.test", []any{"_", "."}, true},
		{"not regex: underscore present fails", ComponentNotRegex{}, "invalid_label.example.test", []any{"_", "."}, false},
		{"not regex: no forbidden chars", ComponentNotRegex{}, "clean.example", []any{"[*?]", "."}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.op.Evaluate(node.New("test", tt.value), nil, tt.operands)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("%s = %v, want %v", tt.op.Name(), got, tt.want)
			}
		})
	}
}

func TestComponentRegexRejectsCollectionNode(t *testing.T) {
	got, err := (ComponentRegex{}).Evaluate(collection("dNSName", "example.com"), nil, []any{"^[a-z]+$"})
	if err != nil {
		t.Fatalf("ComponentRegex.Evaluate() error = %v", err)
	}
	if got {
		t.Fatal("ComponentRegex accepted a collection node; use every for collection traversal")
	}
}

func TestEveryComposesComponentRegex(t *testing.T) {
	names := collection("dNSName", "example.com", "invalid_label.example")

	operands := []any{map[string]any{
		"operator": "componentRegex",
		"operands": []any{"^[a-z]([a-z0-9-]*[a-z0-9])?$"},
	}}
	got, err := DefaultRegistry().Evaluate("every", names, nil, operands)
	if err != nil {
		t.Fatalf("every(componentRegex) error = %v", err)
	}
	if got {
		t.Fatal("every(componentRegex) accepted an invalid value after a valid value")
	}

	names.Children["1"] = node.New("1", "valid-label.example")
	got, err = DefaultRegistry().Evaluate("every", names, nil, operands)
	if err != nil {
		t.Fatalf("every(componentRegex) error = %v", err)
	}
	if !got {
		t.Fatal("every(componentRegex) rejected valid DNS labels")
	}
}

func TestComponentOperatorsUseCollectionElements(t *testing.T) {
	names := node.New("dNSName", nil)
	names.AddElement(node.New("0", "example.com"))
	names.AddElement(node.New("1", "*.example.com"))
	// Named metadata beside indexed elements is not an element.
	names.Children["type"] = node.New("type", "*")

	matched, err := AnyComponentMatches{}.Evaluate(names, nil, []any{`^\*$`})
	if err != nil || matched {
		t.Fatalf("anyComponentMatches matched metadata: %v, %v", matched, err)
	}

	matched, err = AnyComponentMatches{}.Evaluate(names, nil, []any{`^\*\.`})
	if err != nil || !matched {
		t.Fatalf("anyComponentMatches missed an element: %v, %v", matched, err)
	}

	valid, err := ComponentMinLength{}.Evaluate(names, nil, []any{2})
	if err != nil || valid {
		t.Fatalf("componentMinLength = %v, %v; want false for the one-character wildcard label", valid, err)
	}
}

func TestNoComponentMatches(t *testing.T) {
	names := collection("dNSName", "www.example.com", "*.example.com")
	checkEvaluations(t, nil, []evaluationCase{
		{name: "a component matches", op: NoComponentMatches{}, node: names, operands: []any{`^\*\.`}},
		{name: "no component matches", op: NoComponentMatches{}, node: names, operands: []any{`^\*$`}, want: true},
		{name: "single value matches", op: NoComponentMatches{}, node: node.New("name", "*.example.com"), operands: []any{`^\*\.`}},
		{name: "single value does not match", op: NoComponentMatches{}, node: node.New("name", "example.com"), operands: []any{`^\*\.`}, want: true},
		{name: "invalid pattern", op: NoComponentMatches{}, node: names, operands: []any{`(`}, wantErr: true},
		{name: "nil node", op: NoComponentMatches{}, operands: []any{`x`}},
	})
}
