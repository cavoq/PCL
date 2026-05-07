package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestEvery(t *testing.T) {
	op := Every{}

	tests := []struct {
		name     string
		node     *node.Node
		operands []any
		want     bool
		wantErr  bool
	}{
		{
			name:     "nil node returns false",
			node:     nil,
			operands: []any{map[string]any{"check": "present"}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "empty children returns true",
			node: node.New("test", nil),
			operands: []any{map[string]any{"check": "present"}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "all children pass present check",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "value1")
				n.Children["1"] = node.New("1", "value2")
				return n
			}(),
			operands: []any{map[string]any{"check": "present"}},
			want:     true,
			wantErr:  false,
		},
		{
			name: "some children fail notEmpty check",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "value1")
				n.Children["1"] = node.New("1", nil) // nil value = empty
				return n
			}(),
			operands: []any{map[string]any{"check": "notEmpty"}},
			want:     false,
			wantErr:  false,
		},
		{
			name: "all children pass in check with values",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", 1)
				n.Children["1"] = node.New("1", 3)
				n.Children["2"] = node.New("2", 5)
				return n
			}(),
			operands: []any{map[string]any{
				"check": "in",
				"values": []any{1, 3, 5, 7, 9},
			}},
			want:    true,
			wantErr: false,
		},
		{
			name: "one child fails in check",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", 1)
				n.Children["1"] = node.New("1", 2) // 2 not in allowed list
				n.Children["2"] = node.New("2", 5)
				return n
			}(),
			operands: []any{map[string]any{
				"check": "in",
				"values": []any{1, 3, 5, 7, 9},
			}},
			want:    false,
			wantErr: false,
		},
		{
			name: "sub-path check - all pass",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				child0.Children["value"] = node.New("value", 1)
				n.Children["0"] = child0
				child1 := node.New("1", nil)
				child1.Children["value"] = node.New("value", 3)
				n.Children["1"] = child1
				return n
			}(),
			operands: []any{map[string]any{
				"path":  "value",
				"check": "in",
				"values": []any{1, 3, 5},
			}},
			want:    true,
			wantErr: false,
		},
		{
			name: "sub-path check - one fails",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				child0.Children["value"] = node.New("value", 1)
				n.Children["0"] = child0
				child1 := node.New("1", nil)
				child1.Children["value"] = node.New("value", 2) // 2 not allowed
				n.Children["1"] = child1
				return n
			}(),
			operands: []any{map[string]any{
				"path":  "value",
				"check": "in",
				"values": []any{1, 3, 5},
			}},
			want:    false,
			wantErr: false,
		},
		{
			name: "sub-path missing - fails by default",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				child0.Children["value"] = node.New("value", 1)
				n.Children["0"] = child0
				child1 := node.New("1", nil) // no value child
				n.Children["1"] = child1
				return n
			}(),
			operands: []any{map[string]any{
				"path":  "value",
				"check": "present",
			}},
			want:    false,
			wantErr: false,
		},
		{
			name: "sub-path missing - skip with skipMissing",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				child0.Children["value"] = node.New("value", 1)
				n.Children["0"] = child0
				child1 := node.New("1", nil) // no value child, skipped
				n.Children["1"] = child1
				return n
			}(),
			operands: []any{map[string]any{
				"path":        "value",
				"check":       "present",
				"skipMissing": true,
			}},
			want:    true,
			wantErr: false,
		},
		{
			name: "nested sub-path check - simplified",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				child0.Children["a"] = node.New("a", nil)
				child0.Children["a"].Children["b"] = node.New("b", 1)
				n.Children["0"] = child0
				child1 := node.New("1", nil)
				child1.Children["a"] = node.New("a", nil)
				child1.Children["a"].Children["b"] = node.New("b", 3)
				n.Children["1"] = child1
				return n
			}(),
			operands: []any{map[string]any{
				"path":  "a.b",
				"check": "in",
				"values": []any{1, 3, 5, 9},
			}},
			want:    true,
			wantErr: false,
		},
		{
			name: "nested sub-path check",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				ext0 := node.New("extensions", nil)
				reason0 := node.New("2.5.29.21", nil)
				reason0.Children["value"] = node.New("value", 1)
				ext0.Children["2.5.29.21"] = reason0
				child0.Children["extensions"] = ext0
				n.Children["0"] = child0
				child1 := node.New("1", nil)
				ext1 := node.New("extensions", nil)
				reason1 := node.New("2.5.29.21", nil)
				reason1.Children["value"] = node.New("value", 3)
				ext1.Children["2.5.29.21"] = reason1
				child1.Children["extensions"] = ext1
				n.Children["1"] = child1
				return n
			}(),
			operands: []any{map[string]any{
				"path":  "extensions.2.5.29.21.value",
				"check": "in",
				"values": []any{1, 3, 5, 9},
			}},
			want:    true,
			wantErr: false,
		},
		{
			name:     "missing check operand returns error",
			node:     node.New("test", nil),
			operands: []any{map[string]any{"path": "value"}},
			want:     false,
			wantErr:  true,
		},
		{
			name:     "unknown check operator returns error",
			node:     node.New("test", nil),
			operands: []any{map[string]any{"check": "unknownOperator"}},
			want:     false,
			wantErr:  true,
		},
		{
			name:     "no operands returns error",
			node:     node.New("test", nil),
			operands: []any{},
			want:     false,
			wantErr:  true,
		},
		// Test new operator/operands syntax
		{
			name: "new syntax - operator and operands",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", 1)
				n.Children["1"] = node.New("1", 3)
				n.Children["2"] = node.New("2", 5)
				return n
			}(),
			operands: []any{map[string]any{
				"operator": "in",
				"operands": []any{1, 3, 5, 7, 9},
			}},
			want:    true,
			wantErr: false,
		},
		// Test new syntax with wildcard path
		{
			name: "new syntax - wildcard path for AIA scheme",
			node: func() *node.Node {
				n := node.New("accessDescriptions", nil)
				ad0 := node.New("0", nil)
				loc0 := node.New("accessLocation", nil)
				loc0.Children["scheme"] = node.New("scheme", "http")
				ad0.Children["accessLocation"] = loc0
				n.Children["0"] = ad0
				ad1 := node.New("1", nil)
				loc1 := node.New("accessLocation", nil)
				loc1.Children["scheme"] = node.New("scheme", "http")
				ad1.Children["accessLocation"] = loc1
				n.Children["1"] = ad1
				return n
			}(),
			operands: []any{map[string]any{
				"path":     "*.accessLocation.scheme",
				"operator": "eq",
				"operands": []any{"http"},
			}},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, tt.operands)
			if tt.wantErr && err == nil {
				t.Errorf("Every.Evaluate() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Every.Evaluate() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Every.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolvePath(t *testing.T) {
	tests := []struct {
		name string
		node *node.Node
		path string
		want *node.Node
	}{
		{
			name: "empty path returns original node",
			node: node.New("test", "value"),
			path: "",
			want: node.New("test", "value"),
		},
		{
			name: "single level path",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["child"] = node.New("child", "value")
				return n
			}(),
			path: "child",
			want: node.New("child", "value"),
		},
		{
			name: "multi level path",
			node: func() *node.Node {
				n := node.New("test", nil)
				l1 := node.New("l1", nil)
				l2 := node.New("l2", nil)
				l2.Children["l3"] = node.New("l3", "value")
				l1.Children["l2"] = l2
				n.Children["l1"] = l1
				return n
			}(),
			path: "l1.l2.l3",
			want: node.New("l3", "value"),
		},
		{
			name: "path not found returns nil",
			node: node.New("test", nil),
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
			got := resolvePath(tt.node, tt.path)
			if got == nil && tt.want != nil {
				t.Errorf("resolvePath() = nil, want non-nil")
			}
			if got != nil && tt.want == nil {
				t.Errorf("resolvePath() = non-nil, want nil")
			}
			// Compare values if both non-nil
			if got != nil && tt.want != nil {
				if got.Value != tt.want.Value {
					t.Errorf("resolvePath().Value = %v, want %v", got.Value, tt.want.Value)
				}
			}
		})
	}
}
func TestResolvePathWithWildcard(t *testing.T) {
	tests := []struct {
		name         string
		node         *node.Node
		path         string
		wantCount    int    // Expected number of children in result
		wantAnyValue any    // Check if any child has this value
	}{
		// Case 1: Wildcard at end - collect all direct children
		{
			name: "wildcard at end - collect all children",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["a"] = node.New("a", "value1")
				n.Children["b"] = node.New("b", "value2")
				n.Children["c"] = node.New("c", "value3")
				return n
			}(),
			path:      "*",
			wantCount: 3,
		},
		// Case 2: Wildcard in middle - traverse then collect
		{
			name: "wildcard in middle - nested path",
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				nested0 := node.New("nested", nil)
				nested0.Children["value"] = node.New("value", 1)
				child0.Children["nested"] = nested0
				n.Children["0"] = child0
				child1 := node.New("1", nil)
				nested1 := node.New("nested", nil)
				nested1.Children["value"] = node.New("value", 2)
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
			node: func() *node.Node {
				n := node.New("dps", nil)
				dp0 := node.New("0", nil)
				fn0 := node.New("fullName", nil)
				gn0 := node.New("0", nil)
				gn0.Children["scheme"] = node.New("scheme", "http")
				gns0 := node.New("generalNames", nil)
				gns0.Children["0"] = gn0
				fn0.Children["generalNames"] = gns0
				dp0.Children["fullName"] = fn0
				n.Children["0"] = dp0
				dp1 := node.New("1", nil)
				fn1 := node.New("fullName", nil)
				gn1 := node.New("0", nil)
				gn1.Children["scheme"] = node.New("scheme", "http")
				gns1 := node.New("generalNames", nil)
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
			node: func() *node.Node {
				n := node.New("extensions", nil)
				ext0 := node.New("2.5.29.15", nil)
				ext0.Children["critical"] = node.New("critical", true)
				n.Children["2.5.29.15"] = ext0
				ext1 := node.New("2.5.29.37", nil)
				ext1.Children["critical"] = node.New("critical", false)
				n.Children["2.5.29.37"] = ext1
				return n
			}(),
			path:      "*.critical",
			wantCount: 2,
		},
		// Case 5: Wildcard in AIA structure (accessDescriptions area)
		{
			name: "wildcard in AIA - accessLocation scheme",
			node: func() *node.Node {
				n := node.New("accessDescriptions", nil)
				ad0 := node.New("0", nil)
				ad0.Children["accessMethod"] = node.New("accessMethod", "1.3.6.1.5.5.7.48.1")
				loc0 := node.New("accessLocation", nil)
				loc0.Children["scheme"] = node.New("scheme", "http")
				ad0.Children["accessLocation"] = loc0
				n.Children["0"] = ad0
				ad1 := node.New("1", nil)
				ad1.Children["accessMethod"] = node.New("accessMethod", "1.3.6.1.5.5.7.48.2")
				loc1 := node.New("accessLocation", nil)
				loc1.Children["scheme"] = node.New("scheme", "http")
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
			node: func() *node.Node {
				n := node.New("test", nil)
				child0 := node.New("0", nil)
				child0.Children["value"] = node.New("value", 1)
				n.Children["0"] = child0
				child1 := node.New("1", nil) // no value
				n.Children["1"] = child1
				return n
			}(),
			path:      "*.value",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePath(tt.node, tt.path)
			if got == nil {
				if tt.wantCount > 0 {
					t.Errorf("resolvePath() = nil, want node with %d children", tt.wantCount)
				}
				return
			}
			if len(got.Children) != tt.wantCount {
				t.Errorf("resolvePath() returned %d children, want %d", len(got.Children), tt.wantCount)
			}
		})
	}
}
