package node

import (
	"testing"
)

func TestResolveSuccess(t *testing.T) {
	root := New("root", nil)
	root.Children["a"] = New("a", nil)
	root.Children["a"].Children["b"] = New("b", 42)

	n, ok := root.Resolve("a.b")
	if !ok || n.Value != 42 {
		t.Fatalf("expected to resolve a.b with value 42")
	}
}

func TestResolveMissing(t *testing.T) {
	root := New("root", nil)

	_, ok := root.Resolve("a.b")
	if ok {
		t.Fatalf("expected path to be missing")
	}
}
