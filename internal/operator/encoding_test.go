package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestIsIA5String(t *testing.T) {
	op := IsIA5String{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "encoding tag 22 (IA5String) returns true",
			node: func() *node.Node {
				n := node.New("test", "test@example.com")
				n.Children["encoding"] = node.New("encoding", 22)
				return n
			}(),
			want: true,
		},
		{
			name: "encoding tag 19 (PrintableString) returns false",
			node: func() *node.Node {
				n := node.New("test", "Test")
				n.Children["encoding"] = node.New("encoding", 19)
				return n
			}(),
			want: false,
		},
		{
			name: "encoding tag 12 (UTF8String) returns false",
			node: func() *node.Node {
				n := node.New("test", "Test")
				n.Children["encoding"] = node.New("encoding", 12)
				return n
			}(),
			want: false,
		},
		{
			name: "no encoding child with ASCII value returns true",
			node: node.New("test", "example.com"),
			want: true,
		},
		{
			name: "no encoding child with non-ASCII value returns false",
			node: node.New("test", "exampleé.com"),
			want: false,
		},
		{
			name: "no encoding child with non-string value returns false",
			node: node.New("test", 123),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("IsIA5String.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("IsIA5String.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPrintableString(t *testing.T) {
	op := IsPrintableString{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "encoding tag 19 (PrintableString) returns true",
			node: func() *node.Node {
				n := node.New("test", "Test-Org")
				n.Children["encoding"] = node.New("encoding", 19)
				return n
			}(),
			want: true,
		},
		{
			name: "encoding tag 22 (IA5String) returns false",
			node: func() *node.Node {
				n := node.New("test", "test@example.com")
				n.Children["encoding"] = node.New("encoding", 22)
				return n
			}(),
			want: false,
		},
		{
			name: "no encoding child with printable value returns true",
			node: node.New("test", "Test-Org-123"),
			want: true,
		},
		{
			name: "no encoding child with non-printable value returns false",
			node: node.New("test", "Test@Org"),
			want: false,
		},
		{
			name: "no encoding child with unicode value returns false",
			node: node.New("test", "Testé"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("IsPrintableString.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("IsPrintableString.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUTF8String(t *testing.T) {
	op := IsUTF8String{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "encoding tag 12 (UTF8String) returns true",
			node: func() *node.Node {
				n := node.New("test", "Testé")
				n.Children["encoding"] = node.New("encoding", 12)
				return n
			}(),
			want: true,
		},
		{
			name: "encoding tag 19 (PrintableString) returns false",
			node: func() *node.Node {
				n := node.New("test", "Test")
				n.Children["encoding"] = node.New("encoding", 19)
				return n
			}(),
			want: false,
		},
		{
			name: "no encoding child returns false",
			node: node.New("test", "Test"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("IsUTF8String.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("IsUTF8String.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidIA5String(t *testing.T) {
	op := ValidIA5String{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "pure ASCII string returns true",
			node: node.New("test", "example.com"),
			want: true,
		},
		{
			name: "string with non-ASCII returns false",
			node: node.New("test", "exampleé.com"),
			want: false,
		},
		{
			name: "string with 0x80 returns false",
			node: node.New("test", "test\x80"),
			want: false,
		},
		{
			name: "non-string value returns false",
			node: node.New("test", 123),
			want: false,
		},
		{
			name: "children with all ASCII returns true",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "example.com")
				n.Children["1"] = node.New("1", "test.org")
				return n
			}(),
			want: true,
		},
		{
			name: "children with non-ASCII returns false",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "example.com")
				n.Children["1"] = node.New("1", "testé.org")
				return n
			}(),
			want: false,
		},
		{
			name: "children with nil value skipped returns true",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "example.com")
				n.Children["1"] = node.New("1", nil)
				return n
			}(),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("ValidIA5String.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ValidIA5String.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidPrintableString(t *testing.T) {
	op := ValidPrintableString{}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "nil node returns false",
			node: nil,
			want: false,
		},
		{
			name: "valid printable string returns true",
			node: node.New("test", "Test-Org-123"),
			want: true,
		},
		{
			name: "string with letters digits space returns true",
			node: node.New("test", "Test Org 123"),
			want: true,
		},
		{
			name: "string with special chars returns true",
			node: node.New("test", "Test's (Org)+123,-./:=?"),
			want: true,
		},
		{
			name: "string with @ returns false",
			node: node.New("test", "test@example.com"),
			want: false,
		},
		{
			name: "string with unicode returns false",
			node: node.New("test", "Testé"),
			want: false,
		},
		{
			name: "string with underscore returns false",
			node: node.New("test", "test_org"),
			want: false,
		},
		{
			name: "non-string value returns false",
			node: node.New("test", 123),
			want: false,
		},
		{
			name: "children with all printable returns true",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "Test-Org")
				n.Children["1"] = node.New("1", "Org-123")
				return n
			}(),
			want: true,
		},
		{
			name: "children with non-printable returns false",
			node: func() *node.Node {
				n := node.New("test", nil)
				n.Children["0"] = node.New("0", "Test-Org")
				n.Children["1"] = node.New("1", "test@example.com")
				return n
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("ValidPrintableString.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ValidPrintableString.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsASCII(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "empty string is ASCII",
			s:    "",
			want: true,
		},
		{
			name: "simple ASCII string",
			s:    "example.com",
			want: true,
		},
		{
			name: "string with unicode",
			s:    "exampleé.com",
			want: false,
		},
		{
			name: "string with 0x80",
			s:    "test\x80",
			want: false,
		},
		{
			name: "all printable ASCII",
			s:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isASCII(tt.s); got != tt.want {
				t.Errorf("isASCII(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsPrintableStringCompatible(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "empty string is printable",
			s:    "",
			want: true,
		},
		{
			name: "letters and digits",
			s:    "TestOrg123",
			want: true,
		},
		{
			name: "with space",
			s:    "Test Org",
			want: true,
		},
		{
			name: "with apostrophe",
			s:    "Test's",
			want: true,
		},
		{
			name: "with parentheses",
			s:    "(Test)",
			want: true,
		},
		{
			name: "with plus comma dash",
			s:    "Test+Org-123,",
			want: true,
		},
		{
			name: "with dot slash colon",
			s:    "Test./:123",
			want: true,
		},
		{
			name: "with equals question",
			s:    "Test=?123",
			want: true,
		},
		{
			name: "with @ is not printable",
			s:    "test@example.com",
			want: false,
		},
		{
			name: "with underscore is not printable",
			s:    "test_org",
			want: false,
		},
		{
			name: "with unicode is not printable",
			s:    "Testé",
			want: false,
		},
		{
			name: "with exclamation is not printable",
			s:    "Test!",
			want: false,
		},
		{
			name: "with ampersand is not printable",
			s:    "Test&Org",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPrintableStringCompatible(tt.s); got != tt.want {
				t.Errorf("isPrintableStringCompatible(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}