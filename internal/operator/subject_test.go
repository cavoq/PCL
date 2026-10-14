package operator

import (
	"strconv"
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func TestNoDuplicateAttributes(t *testing.T) {
	op := NoDuplicateAttributes{}
	// attribute is a subject attribute node with an oid child unless oid is
	// empty.
	attribute := func(name, value, oid string) *node.Node {
		n := node.New(name, value)
		if oid != "" {
			n.Children["oid"] = node.New("oid", oid)
		}
		return n
	}
	// subject keys each attribute by its name and position, as for repeated
	// attributes.
	subject := func(attributes ...*node.Node) *node.Node {
		n := node.New("subject", nil)
		for index, attribute := range attributes {
			n.Children[attribute.Name+strconv.Itoa(index)] = attribute
		}
		return n
	}
	canonical := func() *node.Node {
		commonNames := attribute("commonName", "example.com", "2.5.4.3")
		for _, value := range []string{"example.com", "example.org"} {
			commonNames.AddElement(attribute("attribute", value, "2.5.4.3"))
		}
		attributes := tree("attributes", nil, commonNames)
		attributes.Children["2.5.4.3"] = commonNames
		return tree("subject", "CN=example.com,CN=example.org", attributes)
	}

	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{"nil node returns false", nil, false},
		{"malformed name returns false", tree("subject", "CN=fallback", node.New("malformed", true)), false},
		{"canonical attribute collection detects duplicate commonName", canonical(), false},
		{"single commonName returns true", subject(attribute("commonName", "example.com", "2.5.4.3")), true},
		{"multiple domainComponent returns true (exempt)", subject(
			attribute("domainComponent", "example", "0.9.2342.19200300.100.1.25"),
			attribute("domainComponent", "com", "0.9.2342.19200300.100.1.25"),
		), true},
		{"multiple streetAddress returns true (exempt)", subject(
			attribute("streetAddress", "Street 1", "2.5.4.9"),
			attribute("streetAddress", "Street 2", "2.5.4.9"),
		), true},
		{"multiple organizationalUnit returns true (exempt)", subject(
			attribute("organizationalUnitName", "OU1", "2.5.4.11"),
			attribute("organizationalUnitName", "OU2", "2.5.4.11"),
		), true},
		{"duplicate commonName by OID returns false", subject(
			attribute("commonName", "example.com", "2.5.4.3"),
			attribute("commonName", "example.org", "2.5.4.3"),
		), false},
		// Without an OID, the node name rather than its suffixed parent key
		// supplies the attribute identity.
		{"duplicate commonName without OID info - only name matches", subject(
			attribute("commonName", "example.com", ""),
			attribute("commonName", "example.org", ""),
		), false},
		{"duplicate organizationName returns false", subject(
			attribute("organizationName", "Org1", "2.5.4.10"),
			attribute("organizationName", "Org2", "2.5.4.10"),
		), false},
		{"duplicate countryName returns false", subject(
			attribute("countryName", "US", "2.5.4.6"),
			attribute("countryName", "GB", "2.5.4.6"),
		), false},
		{"different attributes return true", subject(
			attribute("commonName", "example.com", "2.5.4.3"),
			attribute("organizationName", "Example Org", "2.5.4.10"),
			attribute("countryName", "US", "2.5.4.6"),
		), true},
		{"single child without OID uses node name", subject(attribute("commonName", "example.com", "")), true},
		{"child with OID but not in single instance list returns true",
			subject(attribute("unknownAttribute", "value", "1.2.3.4.5.6")), true},
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
