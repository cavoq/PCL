package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestNoDuplicateAttributes(t *testing.T) {
	op := NoDuplicateAttributes{}

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
			name: "single commonName returns true",
			node: func() *node.Node {
				n := node.New("subject", nil)
				cn := node.New("commonName", "example.com")
				cn.Children["oid"] = node.New("oid", "2.5.4.3")
				n.Children["commonName"] = cn
				return n
			}(),
			want: true,
		},
		{
			name: "multiple domainComponent returns true (exempt)",
			node: func() *node.Node {
				n := node.New("subject", nil)
				dc1 := node.New("domainComponent", "example")
				dc1.Children["oid"] = node.New("oid", "0.9.2342.19200300.100.1.25")
				dc2 := node.New("domainComponent", "com")
				dc2.Children["oid"] = node.New("oid", "0.9.2342.19200300.100.1.25")
				n.Children["domainComponent0"] = dc1
				n.Children["domainComponent1"] = dc2
				return n
			}(),
			want: true,
		},
		{
			name: "multiple streetAddress returns true (exempt)",
			node: func() *node.Node {
				n := node.New("subject", nil)
				sa1 := node.New("streetAddress", "Street 1")
				sa1.Children["oid"] = node.New("oid", "2.5.4.9")
				sa2 := node.New("streetAddress", "Street 2")
				sa2.Children["oid"] = node.New("oid", "2.5.4.9")
				n.Children["streetAddress0"] = sa1
				n.Children["streetAddress1"] = sa2
				return n
			}(),
			want: true,
		},
		{
			name: "multiple organizationalUnit returns true (exempt)",
			node: func() *node.Node {
				n := node.New("subject", nil)
				ou1 := node.New("organizationalUnitName", "OU1")
				ou1.Children["oid"] = node.New("oid", "2.5.4.11")
				ou2 := node.New("organizationalUnitName", "OU2")
				ou2.Children["oid"] = node.New("oid", "2.5.4.11")
				n.Children["organizationalUnitName0"] = ou1
				n.Children["organizationalUnitName1"] = ou2
				return n
			}(),
			want: true,
		},
		{
			name: "duplicate commonName by OID returns false",
			node: func() *node.Node {
				n := node.New("subject", nil)
				cn1 := node.New("commonName", "example.com")
				cn1.Children["oid"] = node.New("oid", "2.5.4.3")
				cn2 := node.New("commonName", "example.org")
				cn2.Children["oid"] = node.New("oid", "2.5.4.3")
				n.Children["commonName0"] = cn1
				n.Children["commonName1"] = cn2
				return n
			}(),
			want: false,
		},
		{
			name: "duplicate commonName without OID info - only name matches",
			node: func() *node.Node {
				n := node.New("subject", nil)
				// When parsed with different keys but both named "commonName"
				// and no OID info, detection relies on name matching
				cn1 := node.New("commonName", "example.com")
				cn2 := node.New("commonName", "example.org")
				n.Children["commonName"] = cn1
				n.Children["commonName_1"] = cn2
				return n
			}(),
			// Expected true because "commonName_1" doesn't match nameToOID["commonName"]
			// This is edge case - duplicate detection requires OID info
			want: true,
		},
		{
			name: "duplicate organizationName returns false",
			node: func() *node.Node {
				n := node.New("subject", nil)
				o1 := node.New("organizationName", "Org1")
				o1.Children["oid"] = node.New("oid", "2.5.4.10")
				o2 := node.New("organizationName", "Org2")
				o2.Children["oid"] = node.New("oid", "2.5.4.10")
				n.Children["organizationName0"] = o1
				n.Children["organizationName1"] = o2
				return n
			}(),
			want: false,
		},
		{
			name: "duplicate countryName returns false",
			node: func() *node.Node {
				n := node.New("subject", nil)
				c1 := node.New("countryName", "US")
				c1.Children["oid"] = node.New("oid", "2.5.4.6")
				c2 := node.New("countryName", "GB")
				c2.Children["oid"] = node.New("oid", "2.5.4.6")
				n.Children["countryName0"] = c1
				n.Children["countryName1"] = c2
				return n
			}(),
			want: false,
		},
		{
			name: "different attributes return true",
			node: func() *node.Node {
				n := node.New("subject", nil)
				cn := node.New("commonName", "example.com")
				cn.Children["oid"] = node.New("oid", "2.5.4.3")
				o := node.New("organizationName", "Example Org")
				o.Children["oid"] = node.New("oid", "2.5.4.10")
				c := node.New("countryName", "US")
				c.Children["oid"] = node.New("oid", "2.5.4.6")
				n.Children["commonName"] = cn
				n.Children["organizationName"] = o
				n.Children["countryName"] = c
				return n
			}(),
			want: true,
		},
		{
			name: "child without OID node is skipped",
			node: func() *node.Node {
				n := node.New("subject", nil)
				cn := node.New("commonName", "example.com")
				// No OID child
				n.Children["commonName"] = cn
				return n
			}(),
			want: true,
		},
		{
			name: "child with OID but not in single instance list returns true",
			node: func() *node.Node {
				n := node.New("subject", nil)
				attr := node.New("unknownAttribute", "value")
				attr.Children["oid"] = node.New("oid", "1.2.3.4.5.6")
				n.Children["unknownAttribute"] = attr
				return n
			}(),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Errorf("NoDuplicateAttributes.Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("NoDuplicateAttributes.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}