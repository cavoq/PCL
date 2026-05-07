package operator

import (
	"net"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestComponentInCIDR(t *testing.T) {
	tests := []struct {
		name     string
		node     *node.Node
		operands []any
		want     bool
	}{
		{
			name: "single IP in range",
			node: node.New("iPAddress", "10.0.0.1"),
			operands: []any{"10.0.0.0/8"},
			want: true,
		},
		{
			name: "single IP not in range",
			node: node.New("iPAddress", "8.8.8.8"),
			operands: []any{"10.0.0.0/8"},
			want: false,
		},
		{
			name: "multiple CIDRs - IP in first",
			node: node.New("iPAddress", "10.1.2.3"),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: true,
		},
		{
			name: "multiple CIDRs - IP in second",
			node: node.New("iPAddress", "192.168.1.1"),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: true,
		},
		{
			name: "multiple CIDRs - IP in neither",
			node: node.New("iPAddress", "1.1.1.1"),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: false,
		},
		{
			name: "IPv6 in range",
			node: node.New("iPAddress", "::1"),
			operands: []any{"::1/128"},
			want: true,
		},
		{
			name: "IPv6 not in range",
			node: node.New("iPAddress", "2001:db8::1"),
			operands: []any{"::1/128", "fe80::/10"},
			want: false,
		},
		{
			name: "IPv6 link-local in range",
			node: node.New("iPAddress", "fe80::1234"),
			operands: []any{"fe80::/10"},
			want: true,
		},
		{
			name: "array of IPs - one in range",
			node: func() *node.Node {
				n := node.New("iPAddress", nil)
				n.Children["0"] = node.New("0", "8.8.8.8")
				n.Children["1"] = node.New("1", "10.0.0.1")
				return n
			}(),
			operands: []any{"10.0.0.0/8"},
			want: true,
		},
		{
			name: "array of IPs - none in range",
			node: func() *node.Node {
				n := node.New("iPAddress", nil)
				n.Children["0"] = node.New("0", "8.8.8.8")
				n.Children["1"] = node.New("1", "1.1.1.1")
				return n
			}(),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: false,
		},
		{
			name: "invalid CIDR operand skipped",
			node: node.New("iPAddress", "10.0.0.1"),
			operands: []any{"invalid-cidr", "10.0.0.0/8"},
			want: true,
		},
		{
			name: "invalid IP address",
			node: node.New("iPAddress", "not-an-ip"),
			operands: []any{"10.0.0.0/8"},
			want: false,
		},
		{
			name: "nil node",
			node: nil,
			operands: []any{"10.0.0.0/8"},
			want: false,
		},
		{
			name: "no operands",
			node: node.New("iPAddress", "10.0.0.1"),
			operands: []any{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := ComponentInCIDR{}
			got, err := op.Evaluate(tt.node, nil, tt.operands)
			if err != nil && tt.want != false {
				t.Errorf("ComponentInCIDR.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ComponentInCIDR.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComponentNotInCIDR(t *testing.T) {
	tests := []struct {
		name     string
		node     *node.Node
		operands []any
		want     bool
	}{
		{
			name: "single IP not in range - passes",
			node: node.New("iPAddress", "8.8.8.8"),
			operands: []any{"10.0.0.0/8"},
			want: true,
		},
		{
			name: "single IP in range - fails",
			node: node.New("iPAddress", "10.0.0.1"),
			operands: []any{"10.0.0.0/8"},
			want: false,
		},
		{
			name: "multiple CIDRs - IP outside all - passes",
			node: node.New("iPAddress", "1.1.1.1"),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"},
			want: true,
		},
		{
			name: "multiple CIDRs - IP in one - fails",
			node: node.New("iPAddress", "172.17.0.1"),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"},
			want: false,
		},
		{
			name: "loopback - fails",
			node: node.New("iPAddress", "127.0.0.1"),
			operands: []any{"127.0.0.0/8"},
			want: false,
		},
		{
			name: "public IP - passes",
			node: node.New("iPAddress", "93.184.216.34"), // example.com
			operands: []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
			want: true,
		},
		{
			name: "IPv6 not in range - passes",
			node: node.New("iPAddress", "2001:db8::1"),
			operands: []any{"::1/128", "fe80::/10"},
			want: true,
		},
		{
			name: "IPv6 link-local - fails",
			node: node.New("iPAddress", "fe80::1"),
			operands: []any{"fe80::/10"},
			want: false,
		},
		{
			name: "array of IPs - all outside - passes",
			node: func() *node.Node {
				n := node.New("iPAddress", nil)
				n.Children["0"] = node.New("0", "8.8.8.8")
				n.Children["1"] = node.New("1", "1.1.1.1")
				return n
			}(),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: true,
		},
		{
			name: "array of IPs - one in range - fails",
			node: func() *node.Node {
				n := node.New("iPAddress", nil)
				n.Children["0"] = node.New("0", "8.8.8.8")
				n.Children["1"] = node.New("1", "192.168.1.1")
				return n
			}(),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: false,
		},
		{
			name: "array of IPs - all in range - fails",
			node: func() *node.Node {
				n := node.New("iPAddress", nil)
				n.Children["0"] = node.New("0", "10.0.0.1")
				n.Children["1"] = node.New("1", "192.168.1.1")
				return n
			}(),
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			want: false,
		},
		{
			name: "nil node",
			node: nil,
			operands: []any{"10.0.0.0/8"},
			want: false,
		},
		{
			name: "no operands",
			node: node.New("iPAddress", "8.8.8.8"),
			operands: []any{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := ComponentNotInCIDR{}
			got, err := op.Evaluate(tt.node, nil, tt.operands)
			if err != nil && tt.want != false {
				t.Errorf("ComponentNotInCIDR.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ComponentNotInCIDR.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCIDROperands(t *testing.T) {
	tests := []struct {
		name     string
		operands []any
		wantLen  int
	}{
		{
			name: "valid CIDRs",
			operands: []any{"10.0.0.0/8", "192.168.0.0/16"},
			wantLen: 2,
		},
		{
			name: "mixed valid and invalid",
			operands: []any{"10.0.0.0/8", "invalid", "192.168.0.0/16"},
			wantLen: 2,
		},
		{
			name: "all invalid",
			operands: []any{"invalid", "also-invalid"},
			wantLen: 0,
		},
		{
			name: "non-string operand",
			operands: []any{123, "10.0.0.0/8"},
			wantLen: 1,
		},
		{
			name: "empty operands",
			operands: []any{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidrs := parseCIDROperands(tt.operands)
			if len(cidrs) != tt.wantLen {
				t.Errorf("parseCIDROperands() length = %v, want %v", len(cidrs), tt.wantLen)
			}
		})
	}
}

func TestIPInCIDRs(t *testing.T) {
	// Setup CIDRs
	_, cidr10, _ := net.ParseCIDR("10.0.0.0/8")
	_, cidr192, _ := net.ParseCIDR("192.168.0.0/16")
	_, cidr172, _ := net.ParseCIDR("172.16.0.0/12")
	_, cidr127, _ := net.ParseCIDR("127.0.0.0/8")

	tests := []struct {
		name  string
		ip    string
		cidrs []*net.IPNet
		want  bool
	}{
		{
			name:  "IP in 10.0.0.0/8",
			ip:    "10.1.2.3",
			cidrs: []*net.IPNet{cidr10},
			want:  true,
		},
		{
			name:  "IP in 192.168.0.0/16",
			ip:    "192.168.100.50",
			cidrs: []*net.IPNet{cidr192},
			want:  true,
		},
		{
			name:  "IP in 172.16.0.0/12 (172.16-31)",
			ip:    "172.20.5.10",
			cidrs: []*net.IPNet{cidr172},
			want:  true,
		},
		{
			name:  "IP at boundary of 172.16.0.0/12",
			ip:    "172.15.255.255", // Just below 172.16
			cidrs: []*net.IPNet{cidr172},
			want:  false,
		},
		{
			name:  "IP at upper boundary of 172.16.0.0/12",
			ip:    "172.31.255.255",
			cidrs: []*net.IPNet{cidr172},
			want:  true,
		},
		{
			name:  "IP outside all CIDRs",
			ip:    "8.8.8.8",
			cidrs: []*net.IPNet{cidr10, cidr192, cidr172, cidr127},
			want:  false,
		},
		{
			name:  "loopback",
			ip:    "127.0.0.1",
			cidrs: []*net.IPNet{cidr127},
			want:  true,
		},
		{
			name:  "invalid IP",
			ip:    "not-an-ip",
			cidrs: []*net.IPNet{cidr10},
			want:  false,
		},
		{
			name:  "empty CIDRs",
			ip:    "10.0.0.1",
			cidrs: []*net.IPNet{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipInCIDRs(tt.ip, tt.cidrs)
			if got != tt.want {
				t.Errorf("ipInCIDRs() = %v, want %v", got, tt.want)
			}
		})
	}
}