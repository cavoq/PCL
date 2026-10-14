package node

import "testing"

func TestLookup(t *testing.T) {
	tests := []struct {
		name string
		node *Node
		path string
		want *Node
	}{
		{
			name: "empty path returns original node",
			node: New("test", "value"),
			path: "",
			want: New("test", "value"),
		},
		{
			name: "single level path",
			node: func() *Node {
				n := New("test", nil)
				n.Children["child"] = New("child", "value")
				return n
			}(),
			path: "child",
			want: New("child", "value"),
		},
		{
			name: "multi level path",
			node: func() *Node {
				n := New("test", nil)
				l1 := New("l1", nil)
				l2 := New("l2", nil)
				l2.Children["l3"] = New("l3", "value")
				l1.Children["l2"] = l2
				n.Children["l1"] = l1
				return n
			}(),
			path: "l1.l2.l3",
			want: New("l3", "value"),
		},
		{
			name: "path not found returns nil",
			node: New("test", nil),
			path: "nonexistent",
			want: nil,
		},
		{
			name: "nil node returns nil",
			node: nil,
			path: "any",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.Lookup(tt.path).Node
			if got == nil && tt.want != nil {
				t.Errorf("Lookup() = nil, want non-nil")
			}
			if got != nil && tt.want == nil {
				t.Errorf("Lookup() = non-nil, want nil")
			}
			// Compare values if both non-nil
			if got != nil && tt.want != nil {
				if got.Value != tt.want.Value {
					t.Errorf("Lookup().Value = %v, want %v", got.Value, tt.want.Value)
				}
			}
		})
	}
}
func TestLookupWithWildcard(t *testing.T) {
	tests := []struct {
		name         string
		node         *Node
		path         string
		wantCount    int // Expected number of children in result
		wantAnyValue any // Check if any child has this value
	}{
		// Case 1: Wildcard at end - collect all direct children
		{
			name: "wildcard at end - collect all children",
			node: func() *Node {
				n := New("test", nil)
				n.Children["a"] = New("a", "value1")
				n.Children["b"] = New("b", "value2")
				n.Children["c"] = New("c", "value3")
				return n
			}(),
			path:      "*",
			wantCount: 3,
		},
		// Case 2: Wildcard in middle - traverse then collect
		{
			name: "wildcard in middle - nested path",
			node: func() *Node {
				n := New("test", nil)
				child0 := New("0", nil)
				nested0 := New("nested", nil)
				nested0.Children["value"] = New("value", 1)
				child0.Children["nested"] = nested0
				n.Children["0"] = child0
				child1 := New("1", nil)
				nested1 := New("nested", nil)
				nested1.Children["value"] = New("value", 2)
				child1.Children["nested"] = nested1
				n.Children["1"] = child1
				return n
			}(),
			path:      "*.nested.value",
			wantCount: 2,
		},
		// Case 3: Double wildcard - deeply nested (CRL DP pattern)
		{
			name: "double wildcard - CRL DP structure",
			node: func() *Node {
				n := New("dps", nil)
				dp0 := New("0", nil)
				fn0 := New("fullName", nil)
				gn0 := New("0", nil)
				gn0.Children["scheme"] = New("scheme", "http")
				gns0 := New("generalNames", nil)
				gns0.Children["0"] = gn0
				fn0.Children["generalNames"] = gns0
				dp0.Children["fullName"] = fn0
				n.Children["0"] = dp0
				dp1 := New("1", nil)
				fn1 := New("fullName", nil)
				gn1 := New("0", nil)
				gn1.Children["scheme"] = New("scheme", "http")
				gns1 := New("generalNames", nil)
				gns1.Children["0"] = gn1
				fn1.Children["generalNames"] = gns1
				dp1.Children["fullName"] = fn1
				n.Children["1"] = dp1
				return n
			}(),
			path:      "*.fullName.generalNames.*.scheme",
			wantCount: 2,
		},
		// Case 4: OID path with wildcard (extensions area)
		{
			name: "wildcard with OID path - extensions",
			node: func() *Node {
				n := New("extensions", nil)
				ext0 := New("2.5.29.15", nil)
				ext0.Children["critical"] = New("critical", true)
				n.Children["2.5.29.15"] = ext0
				ext1 := New("2.5.29.37", nil)
				ext1.Children["critical"] = New("critical", false)
				n.Children["2.5.29.37"] = ext1
				return n
			}(),
			path:      "*.critical",
			wantCount: 2,
		},
		// Case 5: Wildcard in AIA structure (accessDescriptions area)
		{
			name: "wildcard in AIA - accessLocation scheme",
			node: func() *Node {
				n := New("accessDescriptions", nil)
				ad0 := New("0", nil)
				ad0.Children["accessMethod"] = New("accessMethod", "1.3.6.1.5.5.7.48.1")
				loc0 := New("accessLocation", nil)
				loc0.Children["scheme"] = New("scheme", "http")
				ad0.Children["accessLocation"] = loc0
				n.Children["0"] = ad0
				ad1 := New("1", nil)
				ad1.Children["accessMethod"] = New("accessMethod", "1.3.6.1.5.5.7.48.2")
				loc1 := New("accessLocation", nil)
				loc1.Children["scheme"] = New("scheme", "http")
				ad1.Children["accessLocation"] = loc1
				n.Children["1"] = ad1
				return n
			}(),
			path:      "*.accessLocation.scheme",
			wantCount: 2,
		},
		// Case 6: Missing children - wildcard skips
		{
			name: "wildcard with missing children",
			node: func() *Node {
				n := New("test", nil)
				child0 := New("0", nil)
				child0.Children["value"] = New("value", 1)
				n.Children["0"] = child0
				child1 := New("1", nil) // no value
				n.Children["1"] = child1
				return n
			}(),
			path:      "*.value",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.Lookup(tt.path).Node
			if got == nil {
				if tt.wantCount > 0 {
					t.Errorf("Lookup() = nil, want node with %d children", tt.wantCount)
				}
				return
			}
			if len(got.Children) != tt.wantCount {
				t.Errorf("Lookup() returned %d children, want %d", len(got.Children), tt.wantCount)
			}
		})
	}
}

func TestLookupCombinesDottedKeys(t *testing.T) {
	root := New("root", nil)
	extension := New("2.5.29.15", nil)
	extension.Children["critical"] = New("critical", true)
	root.Children["2.5.29.15"] = extension
	root.Children["example.com"] = New("example.com", "dns")

	if got := root.Lookup("2.5.29.15.critical").Node; got == nil || got.Value != true {
		t.Fatalf("Lookup OID key = %v, want critical=true", got)
	}
	if got := root.Lookup("example.com").Node; got == nil || got.Value != "dns" {
		t.Fatalf("Lookup dotted non-numeric key = %v, want dns", got)
	}
}

func TestLookupDoesNotSkipOwnName(t *testing.T) {
	element := New("value", nil)
	element.Children["value"] = New("value", 7)

	if got := element.Lookup("value").Node; got == nil || got.Value != 7 {
		t.Fatalf("Lookup(value) = %v, want child with value 7", got)
	}
	if got, ok := element.Resolve("value"); !ok || got != element {
		t.Fatalf("Resolve(value) should treat the leading own name as the root")
	}
}

func TestLookupWildcardReportsPartialMatch(t *testing.T) {
	root := New("root", nil)
	first := New("0", nil)
	first.Children["value"] = New("value", 1)
	root.Children["0"] = first
	root.Children["1"] = New("1", nil)

	resolution := root.Lookup("*.value")
	if resolution.Node == nil || len(resolution.Node.Children) != 1 {
		t.Fatalf("Lookup(*.value) = %v, want one match", resolution.Node)
	}
	if !resolution.Partial {
		t.Fatal("Lookup(*.value) should report the unresolved branch")
	}
}

func TestResolveNilNode(t *testing.T) {
	var n *Node
	if _, ok := n.Resolve("a"); ok {
		t.Fatal("Resolve on nil node should fail")
	}
}
