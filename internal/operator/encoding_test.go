package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestStringEncodingOperators(t *testing.T) {
	encoded := func(value string, tag int) *node.Node {
		return tree("test", value, node.New("encoding", tag))
	}
	checkEvaluations(t, nil, []evaluationCase{
		{name: "IA5String: nil node returns false", op: IsIA5String{}},
		{name: "IA5String: encoding tag 22 returns true", op: IsIA5String{}, node: encoded("test@example.com", 22), want: true},
		{name: "IA5String: encoding tag 19 returns false", op: IsIA5String{}, node: encoded("Test", 19)},
		{name: "IA5String: encoding tag 12 returns false", op: IsIA5String{}, node: encoded("Test", 12)},
		{name: "IA5String: no encoding child with ASCII value returns false", op: IsIA5String{}, node: node.New("test", "example.com")},
		{name: "IA5String: no encoding child with non-ASCII value returns false", op: IsIA5String{}, node: node.New("test", "exampleé.com")},
		{name: "IA5String: no encoding child with non-string value returns false", op: IsIA5String{}, node: node.New("test", 123)},

		{name: "PrintableString: nil node returns false", op: IsPrintableString{}},
		{name: "PrintableString: encoding tag 19 returns true", op: IsPrintableString{}, node: encoded("Test-Org", 19), want: true},
		{name: "PrintableString: encoding tag 22 returns false", op: IsPrintableString{}, node: encoded("test@example.com", 22)},
		{name: "PrintableString: no encoding child with printable value returns false", op: IsPrintableString{}, node: node.New("test", "Test-Org-123")},
		{name: "PrintableString: no encoding child with non-printable value returns false", op: IsPrintableString{}, node: node.New("test", "Test@Org")},
		{name: "PrintableString: no encoding child with unicode value returns false", op: IsPrintableString{}, node: node.New("test", "Testé")},

		{name: "UTF8String: nil node returns false", op: IsUTF8String{}},
		{name: "UTF8String: encoding tag 12 returns true", op: IsUTF8String{}, node: encoded("Testé", 12), want: true},
		{name: "UTF8String: encoding tag 19 returns false", op: IsUTF8String{}, node: encoded("Test", 19)},
		{name: "UTF8String: no encoding child returns false", op: IsUTF8String{}, node: node.New("test", "Test")},

		{name: "valid IA5String: nil node returns false", op: ValidIA5String{}},
		{name: "valid IA5String: pure ASCII string returns true", op: ValidIA5String{}, node: node.New("test", "example.com"), want: true},
		{name: "valid IA5String: string with non-ASCII returns false", op: ValidIA5String{}, node: node.New("test", "exampleé.com")},
		{name: "valid IA5String: string with 0x80 returns false", op: ValidIA5String{}, node: node.New("test", "test\x80")},
		{name: "valid IA5String: non-string value returns false", op: ValidIA5String{}, node: node.New("test", 123)},
		{name: "valid IA5String: collection node returns false", op: ValidIA5String{}, node: collection("test", "example.com", "test.org")},

		{name: "valid PrintableString: nil node returns false", op: ValidPrintableString{}},
		{name: "valid PrintableString: valid printable string returns true", op: ValidPrintableString{}, node: node.New("test", "Test-Org-123"), want: true},
		{name: "valid PrintableString: letters digits space returns true", op: ValidPrintableString{}, node: node.New("test", "Test Org 123"), want: true},
		{name: "valid PrintableString: special chars returns true", op: ValidPrintableString{}, node: node.New("test", "Test's (Org)+123,-./:=?"), want: true},
		{name: "valid PrintableString: @ returns false", op: ValidPrintableString{}, node: node.New("test", "test@example.com")},
		{name: "valid PrintableString: unicode returns false", op: ValidPrintableString{}, node: node.New("test", "Testé")},
		{name: "valid PrintableString: underscore returns false", op: ValidPrintableString{}, node: node.New("test", "test_org")},
		{name: "valid PrintableString: non-string value returns false", op: ValidPrintableString{}, node: node.New("test", 123)},
		{name: "valid PrintableString: children with all printable returns true", op: ValidPrintableString{},
			node: collection("test", "Test-Org", "Org-123"), want: true},
		{name: "valid PrintableString: children with non-printable returns false", op: ValidPrintableString{},
			node: collection("test", "Test-Org", "test@example.com")},
	})
}

func TestEveryComposesValidIA5String(t *testing.T) {
	names := collection("dNSName", "example.com", "exampleé.test")
	operands := []any{map[string]any{"operator": "validIA5String"}}
	got, err := DefaultRegistry().Evaluate("every", names, nil, operands)
	if err != nil {
		t.Fatalf("every(validIA5String) error = %v", err)
	}
	if got {
		t.Fatal("every(validIA5String) accepted a non-ASCII value after an ASCII value")
	}

	names.Children["1"] = node.New("1", "example.test")
	got, err = DefaultRegistry().Evaluate("every", names, nil, operands)
	if err != nil {
		t.Fatalf("every(validIA5String) error = %v", err)
	}
	if !got {
		t.Fatal("every(validIA5String) rejected ASCII values")
	}
}
