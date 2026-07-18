package node

import "testing"

func TestCollectionElementsPrefersNumericIndices(t *testing.T) {
	one := New("one", 1)
	two := New("two", 2)
	ten := New("ten", 10)
	collection := New("items", nil)
	collection.Children["10"] = ten
	collection.Children["2"] = two
	collection.Children["1"] = one
	collection.Children["count"] = New("count", 3)
	collection.Children["first"] = one

	assertElements(t, CollectionElements(collection), one, two, ten)
}

func TestCollectionElementsFallsBackToUniqueNamedChildren(t *testing.T) {
	alpha := New("alpha", "a")
	beta := New("beta", "b")
	object := New("object", nil)
	object.Children["zeta"] = beta
	object.Children["alias"] = alpha
	object.Children["alpha"] = alpha
	object.Children["nil"] = nil

	assertElements(t, CollectionElements(object), alpha, beta)
}

func TestCollectionElementsHandlesEmptyNodes(t *testing.T) {
	if elements := CollectionElements(nil); len(elements) != 0 {
		t.Fatalf("CollectionElements(nil) returned %d elements", len(elements))
	}
	if elements := CollectionElements(New("empty", nil)); len(elements) != 0 {
		t.Fatalf("CollectionElements(empty) returned %d elements", len(elements))
	}
}

func TestAddElementIgnoresMetadataKeys(t *testing.T) {
	collection := New("items", nil)
	collection.Children["count"] = New("count", 2)
	first := New("first", nil)
	second := New("second", nil)
	collection.Children["0"] = first

	collection.AddElement(second)

	if got := collection.Children["1"]; got != second {
		t.Fatalf("AddElement stored element at key 1 as %p, want %p", got, second)
	}
	assertElements(t, CollectionElements(collection), first, second)
}

func assertElements(t *testing.T, got []*Node, want ...*Node) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d elements, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("element %d = %p (%q), want %p (%q)", index, got[index], got[index].Name, want[index], want[index].Name)
		}
	}
}
