package operator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/data"
	"github.com/cavoq/PCL/internal/node"
)

func getTestPSLPath() string {
	// Try multiple locations
	candidates := []string{
		"data/public_suffix_list.dat",                          // From project root
		filepath.Join("..", "..", "data", "public_suffix_list.dat"), // From internal/operator
	}

	// Also check if we're in test mode with cwd
	if cwd, _ := os.Getwd(); cwd != "" {
		candidates = append(candidates,
			filepath.Join(cwd, "data", "public_suffix_list.dat"),
			filepath.Join(cwd, "..", "..", "data", "public_suffix_list.dat"),
		)
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func TestTLDRegistered(t *testing.T) {
	pslPath := getTestPSLPath()
	if pslPath == "" {
		t.Skip("PSL file not found, skipping test")
	}
	if err := data.DefaultLoader.LoadPSL(pslPath); err != nil {
		t.Skipf("PSL not available: %v", err)
	}

	tests := []struct {
		name     string
		node     *node.Node
		want     bool
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
	pslPath := getTestPSLPath()
	if pslPath == "" {
		t.Skip("PSL file not found, skipping test")
	}
	if err := data.DefaultLoader.LoadPSL(pslPath); err != nil {
		t.Skipf("PSL not available: %v", err)
	}

	tests := []struct {
		name     string
		node     *node.Node
		want     bool
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
	pslPath := getTestPSLPath()
	if pslPath == "" {
		t.Skip("PSL file not found, skipping test")
	}
	if err := data.DefaultLoader.LoadPSL(pslPath); err != nil {
		t.Skipf("PSL not available: %v", err)
	}

	tests := []struct {
		name     string
		node     *node.Node
		want     bool
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