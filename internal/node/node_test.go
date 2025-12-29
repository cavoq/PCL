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

func TestResolveOIDKey(t *testing.T) {
	root := New("root", nil)
	root.Children["extensions"] = New("extensions", nil)
	root.Children["extensions"].Children["2.5.29.15"] = New("2.5.29.15", nil)
	root.Children["extensions"].Children["2.5.29.15"].Children["critical"] = New("critical", true)

	n, ok := root.Resolve("extensions.2.5.29.15.critical")
	if !ok || n.Value != true {
		t.Fatalf("expected to resolve extensions.2.5.29.15.critical with value true")
	}
}
