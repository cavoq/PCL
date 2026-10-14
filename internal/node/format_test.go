package node

import (
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestValueKindAndFormatValue(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	tests := []struct {
		value     any
		kind      string
		formatted string
	}{
		{nil, "", ""},
		{"text", "string", "text"},
		{uint16(7), "int", "7"},
		{big.NewInt(-12), "int", "-12"},
		{true, "bool", "true"},
		{[]byte{0xde, 0xad}, "bytes", "dead"},
		{when, "time", "2026-01-02T02:04:05Z"},
		{[]string{"a"}, "[]string", "[a]"},
	}
	for _, test := range tests {
		if kind := ValueKind(test.value); kind != test.kind {
			t.Errorf("ValueKind(%#v) = %q, want %q", test.value, kind, test.kind)
		}
		if formatted := FormatValue(test.value); formatted != test.formatted {
			t.Errorf("FormatValue(%#v) = %q, want %q", test.value, formatted, test.formatted)
		}
	}
}

func TestSortedChildKeysOrdersIndexesNumerically(t *testing.T) {
	n := New("collection", nil)
	for _, key := range []string{"count", "10", "2", "0", "raw"} {
		n.Children[key] = New(key, nil)
	}
	if got, want := SortedChildKeys(n), []string{"0", "2", "10", "count", "raw"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SortedChildKeys = %v, want %v", got, want)
	}
}

func TestPrintDrawsBranches(t *testing.T) {
	root := New("root", nil)
	child := New("child", nil)
	child.Children["leaf"] = New("leaf", []byte{0x01})
	root.Children["child"] = child
	root.Children["value"] = New("value", 3)

	want := "root\n├── child\n│   └── leaf: 01\n└── value: 3\n"
	if got := root.Print(); got != want {
		t.Fatalf("Print =\n%s\nwant\n%s", got, want)
	}
}

func TestPathsStartAtTheRootName(t *testing.T) {
	root := New("certificate", nil)
	root.Children["2.5.29.15"] = New("2.5.29.15", nil)
	root.Children["2.5.29.15"].Children["critical"] = New("critical", true)

	var paths []string
	for _, entry := range Paths(root) {
		paths = append(paths, entry.Path)
	}
	want := []string{"certificate", "certificate.2.5.29.15", "certificate.2.5.29.15.critical"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("Paths = %v, want %v", paths, want)
	}
}
