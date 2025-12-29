package node_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestResolveSuccess(t *testing.T) {
	root := node.New("root", nil)
	root.Children["a"] = node.New("a", nil)
	root.Children["a"].Children["b"] = node.New("b", 42)

	n, ok := root.Resolve("a.b")
	if !ok || n.Value != 42 {
		t.Fatalf("expected to resolve a.b with value 42")
	}
}

func TestResolveMissing(t *testing.T) {
	root := node.New("root", nil)
	_, ok := root.Resolve("a.b")
	if ok {
		t.Fatalf("expected path to be missing")
	}
}

func TestResolveOIDKey(t *testing.T) {
	root := node.New("root", nil)
	root.Children["extensions"] = node.New("extensions", nil)
	root.Children["extensions"].Children["2.5.29.15"] = node.New("2.5.29.15", nil)
	root.Children["extensions"].Children["2.5.29.15"].Children["critical"] = node.New("critical", true)

	n, ok := root.Resolve("extensions.2.5.29.15.critical")
	if !ok || n.Value != true {
		t.Fatalf("expected to resolve extensions.2.5.29.15.critical with value true")
	}
}
