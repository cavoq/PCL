package operator

import (
	"net"
	"testing"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/cert"
)

func TestNameConstraintsValidNilContext(t *testing.T) {
	op := NameConstraintsValid{}
	got, err := op.Evaluate(nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("nil context should return false")
	}
}

func TestNameConstraintsValidNoChain(t *testing.T) {
	op := NameConstraintsValid{}
	ctx := &EvaluationContext{
		Cert:  &cert.Info{Cert: &x509.Certificate{}},
		Chain: nil,
	}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got {
		t.Error("no chain should return false")
	}
}

func TestNameConstraintsValidChains(t *testing.T) {
	subtrees := func(names ...string) []x509.GeneralSubtreeString {
		result := make([]x509.GeneralSubtreeString, len(names))
		for index, name := range names {
			result[index] = x509.GeneralSubtreeString{Data: name}
		}
		return result
	}
	ipSubtree := func(cidr string) []x509.GeneralSubtreeIP {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		return []x509.GeneralSubtreeIP{{Data: *network}}
	}
	emailLeaf := func(address string) *x509.Certificate {
		return &x509.Certificate{
			EmailAddresses: []string{address},
			Extensions:     []pkix.Extension{{Id: zasn1.ObjectIdentifier{2, 5, 29, 17}}},
		}
	}

	tests := []struct {
		name string
		leaf *x509.Certificate
		// cas are the issuers of leaf, nearest first.
		cas  []*x509.Certificate
		want bool
	}{
		{"no constraints pass", &x509.Certificate{DNSNames: []string{"example.com"}},
			[]*x509.Certificate{{}}, true},
		{"DNS within permitted passes", &x509.Certificate{DNSNames: []string{"foo.example.com"}},
			[]*x509.Certificate{{PermittedDNSNames: subtrees(".example.com")}}, true},
		{"DNS outside permitted fails", &x509.Certificate{DNSNames: []string{"foo.other.com"}},
			[]*x509.Certificate{{PermittedDNSNames: subtrees(".example.com")}}, false},
		{"DNS in excluded fails", &x509.Certificate{DNSNames: []string{"foo.bad.com"}},
			[]*x509.Certificate{{ExcludedDNSNames: subtrees(".bad.com")}}, false},
		{"email within permitted passes", emailLeaf("user@example.com"),
			[]*x509.Certificate{{PermittedEmailAddresses: subtrees("example.com")}}, true},
		{"email outside permitted fails", emailLeaf("user@other.com"),
			[]*x509.Certificate{{PermittedEmailAddresses: subtrees("example.com")}}, false},
		{"IP within permitted passes", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.168.1.100")}},
			[]*x509.Certificate{{PermittedIPAddresses: ipSubtree("192.168.0.0/16")}}, true},
		{"IP outside permitted fails", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
			[]*x509.Certificate{{PermittedIPAddresses: ipSubtree("192.168.0.0/16")}}, false},
		{"IP in excluded fails", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.168.1.100")}},
			[]*x509.Certificate{{ExcludedIPAddresses: ipSubtree("192.168.1.0/24")}}, false},
		{"URI within permitted passes", &x509.Certificate{URIs: []string{"https://foo.example.com/path"}},
			[]*x509.Certificate{{PermittedURIs: subtrees(".example.com")}}, true},
		{"multiple CA constraints pass", &x509.Certificate{DNSNames: []string{"foo.example.com"}},
			[]*x509.Certificate{{PermittedDNSNames: subtrees(".example.com")}, {ExcludedDNSNames: subtrees(".bad.com")}}, true},
		// A name within the intermediate's permitted set but not the root's
		// fails; under union semantics it would pass.
		{"name outside the root's permitted set fails", &x509.Certificate{DNSNames: []string{"foo.other.com"}},
			[]*x509.Certificate{{PermittedDNSNames: subtrees(".other.com")}, {PermittedDNSNames: subtrees(".example.com")}}, false},
		{"name within both permitted sets passes", &x509.Certificate{DNSNames: []string{"foo.sub.example.com"}},
			[]*x509.Certificate{{PermittedDNSNames: subtrees(".sub.example.com")}, {PermittedDNSNames: subtrees(".example.com")}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := []*cert.Info{{Cert: tt.leaf}}
			for _, ca := range tt.cas {
				chain = append(chain, &cert.Info{Cert: ca})
			}
			ctx := &EvaluationContext{Cert: &cert.Info{Cert: tt.leaf}, Chain: chain}
			got, err := NameConstraintsValid{}.Evaluate(nil, ctx, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("nameConstraintsValid = %v, want %v", got, tt.want)
			}
		})
	}
}
