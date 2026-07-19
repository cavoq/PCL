package cert

import (
	"net"
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestNameConstraintsValidSupportedNameForms(t *testing.T) {
	_, permittedNetwork, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{
		PermittedDNSNames:       []x509.GeneralSubtreeString{{Data: ".example.test"}},
		PermittedEmailAddresses: []x509.GeneralSubtreeString{{Data: "example.test"}},
		PermittedURIs:           []x509.GeneralSubtreeString{{Data: ".example.test"}},
		PermittedIPAddresses:    []x509.GeneralSubtreeIP{{Data: *permittedNetwork}},
	}

	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{
			name: "all supported forms permitted",
			certificate: &x509.Certificate{
				DNSNames:       []string{"www.example.test"},
				EmailAddresses: []string{"user@example.test"},
				URIs:           []string{"https://service.example.test/path"},
				IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
				Extensions: []pkix.Extension{
					extensionForCertificateTest(oid.SubjectAlternativeName),
				},
			},
			want: true,
		},
		{
			name:        "DNS outside permitted subtree",
			certificate: &x509.Certificate{DNSNames: []string{"www.other.test"}},
		},
		{
			name: "email outside permitted subtree",
			certificate: &x509.Certificate{
				EmailAddresses: []string{"user@other.test"},
				Extensions: []pkix.Extension{
					extensionForCertificateTest(oid.SubjectAlternativeName),
				},
			},
		},
		{
			name:        "URI outside permitted subtree",
			certificate: &x509.Certificate{URIs: []string{"https://service.other.test/path"}},
		},
		{
			name:        "IP outside permitted subtree",
			certificate: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("198.51.100.10")}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := &Info{Cert: test.certificate, Position: 0}
			chain := []*Info{current, {Cert: issuer, Position: 1}}
			if got := NameConstraintsValid(current, chain); got != test.want {
				t.Fatalf("NameConstraintsValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNameConstraintsValidIntersectsPermittedAndUnionsExcluded(t *testing.T) {
	leaf := &Info{Cert: &x509.Certificate{DNSNames: []string{"www.sub.example.test"}}, Position: 0}
	intermediate := &Info{Cert: &x509.Certificate{
		PermittedDNSNames: []x509.GeneralSubtreeString{{Data: ".sub.example.test"}},
	}, Position: 1}
	root := &Info{Cert: &x509.Certificate{
		PermittedDNSNames: []x509.GeneralSubtreeString{{Data: ".example.test"}},
		ExcludedDNSNames:  []x509.GeneralSubtreeString{{Data: ".blocked.example.test"}},
	}, Position: 2}
	chain := []*Info{leaf, intermediate, root}
	if !NameConstraintsValid(leaf, chain) {
		t.Fatal("name inside both permitted sets failed")
	}

	leaf.Cert.DNSNames = []string{"www.other.test"}
	if NameConstraintsValid(leaf, chain) {
		t.Fatal("name outside root permitted set passed")
	}

	leaf.Cert.DNSNames = []string{"www.blocked.example.test"}
	if NameConstraintsValid(leaf, chain) {
		t.Fatal("name in excluded union passed")
	}
}

func TestNameConstraintsValidConstrainsSubjectEmailWhenSANAbsent(t *testing.T) {
	issuer := &Info{Cert: &x509.Certificate{
		ExcludedEmailAddresses: []x509.GeneralSubtreeString{{Data: ".example.test"}},
	}, Position: 1}
	leaf := &Info{Cert: &x509.Certificate{
		Subject: pkix.Name{EmailAddress: []string{"user@blocked.example.test"}},
	}, Position: 0}

	if NameConstraintsValid(leaf, []*Info{leaf, issuer}) {
		t.Fatal("excluded subject-DN email passed when SAN was absent")
	}

	leaf.Cert.Extensions = []pkix.Extension{extensionForCertificateTest(oid.SubjectAlternativeName)}
	if !NameConstraintsValid(leaf, []*Info{leaf, issuer}) {
		t.Fatal("subject-DN email was constrained even though SAN was present")
	}
}

func TestNameConstraintsValidSelfIssuedExemption(t *testing.T) {
	root := &Info{Cert: &x509.Certificate{
		PermittedDNSNames: []x509.GeneralSubtreeString{{Data: ".example.test"}},
	}, Position: 2}
	rollover := &Info{Cert: &x509.Certificate{
		Subject:  pkix.Name{CommonName: "rollover"},
		Issuer:   pkix.Name{CommonName: "rollover"},
		DNSNames: []string{"outside.other.test"},
		PermittedDNSNames: []x509.GeneralSubtreeString{
			{Data: ".example.test"},
		},
	}, Position: 1}
	leaf := &Info{Cert: &x509.Certificate{DNSNames: []string{"www.example.test"}}, Position: 0}
	chain := []*Info{leaf, rollover, root}

	if !NameConstraintsValid(rollover, chain) {
		t.Fatal("issuer constraints were applied to a non-target self-issued certificate")
	}
	if !NameConstraintsValid(leaf, chain) {
		t.Fatal("self-issued certificate's own constraints were not applied to a permitted leaf")
	}
	leaf.Cert.DNSNames = []string{"www.other.test"}
	if NameConstraintsValid(leaf, chain) {
		t.Fatal("self-issued certificate's own constraints did not restrict the leaf")
	}

	selfIssuedTarget := &Info{Cert: &x509.Certificate{
		Subject:  pkix.Name{CommonName: "target"},
		Issuer:   pkix.Name{CommonName: "target"},
		DNSNames: []string{"outside.other.test"},
	}, Position: 0}
	if NameConstraintsValid(selfIssuedTarget, []*Info{selfIssuedTarget, root}) {
		t.Fatal("self-issued final target incorrectly received the exemption")
	}
}

func TestNameConstraintsValidRequiresCurrentChainMember(t *testing.T) {
	current := &Info{Cert: &x509.Certificate{}}
	if NameConstraintsValid(nil, []*Info{current}) {
		t.Fatal("nil current passed")
	}
	if NameConstraintsValid(current, nil) {
		t.Fatal("empty chain passed")
	}
	if NameConstraintsValid(current, []*Info{{Cert: &x509.Certificate{}}}) {
		t.Fatal("certificate outside supplied chain passed")
	}
}

func TestMatchesDNSConstraintBoundary(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		want       bool
	}{
		{name: "example.test", constraint: ".example.test"},
		{name: "www.example.test", constraint: ".example.test", want: true},
		{name: "example.test", constraint: "example.test", want: true},
		{name: "www.example.test", constraint: "example.test", want: true},
	}
	for _, test := range tests {
		if got := matchesDNS(test.name, test.constraint); got != test.want {
			t.Errorf("matchesDNS(%q, %q) = %v, want %v", test.name, test.constraint, got, test.want)
		}
	}
}

func TestNameConstraintsEmailAndURIHostBoundaries(t *testing.T) {
	t.Run("email host constraint does not include subdomains", func(t *testing.T) {
		if !matchesEmail("user@example.test", "example.test") {
			t.Fatal("exact email host did not match")
		}
		if matchesEmail("user@sub.example.test", "example.test") {
			t.Fatal("host-only email constraint matched a subdomain")
		}
		if !matchesEmail("user@sub.example.test", ".example.test") {
			t.Fatal("email domain constraint did not match a subdomain")
		}
	})

	t.Run("email mailbox keeps local-part case and folds host case", func(t *testing.T) {
		if matchesEmail("admin@example.test", "Admin@example.test") {
			t.Fatal("mailbox constraint ignored local-part case")
		}
		if !matchesEmail("Admin@EXAMPLE.TEST", "Admin@example.test") {
			t.Fatal("mailbox constraint did not compare the host case-insensitively")
		}
	})

	t.Run("URI host constraint does not include subdomains", func(t *testing.T) {
		if !matchesURIConstraint("https://example.test/path", []string{"example.test"}, nil) {
			t.Fatal("exact URI host did not match")
		}
		if matchesURIConstraint("https://sub.example.test/path", []string{"example.test"}, nil) {
			t.Fatal("host-only URI constraint matched a subdomain")
		}
		if !matchesURIConstraint("https://sub.example.test/path", []string{".example.test"}, nil) {
			t.Fatal("URI domain constraint did not match a subdomain")
		}
	})

	for _, uri := range []string{
		"relative/path",
		"mailto:user@example.test",
		"https://192.0.2.1/path",
		"https://localhost/path",
	} {
		t.Run("constrained URI rejects "+uri, func(t *testing.T) {
			if matchesURIConstraint(uri, nil, []string{".blocked.example.test"}) {
				t.Fatalf("constrained URI %q without an FQDN host passed", uri)
			}
		})
	}

	if !matchesURIConstraint("relative/path", nil, nil) {
		t.Fatal("an unconstrained URI was rejected by Name Constraints")
	}
}
