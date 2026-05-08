package operator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/data"
	"github.com/cavoq/PCL/internal/node"
)

func loadTestPSL(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	pslPath := filepath.Join(tmpDir, "public_suffix_list.dat")
	content := `// Public Suffix List test data
// ===BEGIN ICANN DOMAINS===
com
net
org
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
`

	if err := os.WriteFile(pslPath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test PSL: %v", err)
	}

	oldLoader := data.DefaultLoader
	data.DefaultLoader = &data.Loader{}
	t.Cleanup(func() {
		data.DefaultLoader = oldLoader
	})

	if err := data.DefaultLoader.LoadPSL(pslPath); err != nil {
		t.Fatalf("failed to load test PSL: %v", err)
	}
}

func TestTLDRegistered(t *testing.T) {
	loadTestPSL(t)

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "valid TLD .com",
			node: node.New("dNSName", "example.com"),
			want: true,
		},
		{
			name: "valid TLD .net",
			node: node.New("dNSName", "test.net"),
			want: true,
		},
		{
			name: "reserved TLD .test",
			node: node.New("dNSName", "example.test"),
			want: false,
		},
		{
			name: "reserved TLD .local",
			node: node.New("dNSName", "server.local"),
			want: false,
		},
		{
			name: "reserved TLD .internal",
			node: node.New("dNSName", "host.internal"),
			want: false,
		},
	}

	op := TLDRegistered{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("TLDRegistered(%s) = %v, want %v", tt.node.Value, got, tt.want)
			}
		})
	}
}

func TestComponentTLDRegistered(t *testing.T) {
	loadTestPSL(t)

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "all domains have valid TLDs",
			node: func() *node.Node {
				n := node.New("dNSName", nil)
				n.Children["0"] = node.New("0", "example.com")
				n.Children["1"] = node.New("1", "test.org")
				return n
			}(),
			want: true,
		},
		{
			name: "one domain has invalid TLD",
			node: func() *node.Node {
				n := node.New("dNSName", nil)
				n.Children["0"] = node.New("0", "example.com")
				n.Children["1"] = node.New("1", "server.local")
				return n
			}(),
			want: false,
		},
		{
			name: "all domains have invalid TLDs",
			node: func() *node.Node {
				n := node.New("dNSName", nil)
				n.Children["0"] = node.New("0", "server.test")
				n.Children["1"] = node.New("1", "host.internal")
				return n
			}(),
			want: false,
		},
	}

	op := ComponentTLDRegistered{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ComponentTLDRegistered = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComponentIsPublicSuffix(t *testing.T) {
	loadTestPSL(t)

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{
			name: "wildcard *.com - FQDN portion is public suffix",
			node: node.New("dNSName", "*.com"),
			want: true,
		},
		{
			name: "wildcard *.example.com - not public suffix",
			node: node.New("dNSName", "*.example.com"),
			want: false,
		},
		{
			name: "wildcard *.github.io - FQDN is private public suffix",
			node: node.New("dNSName", "*.github.io"),
			want: true,
		},
		{
			name: "non-wildcard normal domain",
			node: node.New("dNSName", "www.example.com"),
			want: false,
		},
	}

	op := ComponentIsPublicSuffix{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ComponentIsPublicSuffix(%s) = %v, want %v", tt.node.Value, got, tt.want)
			}
		})
	}
}
