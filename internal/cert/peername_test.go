package cert

import (
	"net"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestParsePeerName(t *testing.T) {
	tests := []struct {
		value   string
		want    PeerName
		wantErr bool
	}{
		{value: "example.com", want: PeerName{Kind: PeerNameDNS, Value: "example.com"}},
		{value: "example.com.", want: PeerName{Kind: PeerNameDNS, Value: "example.com"}},
		{value: "xn--bcher-kva.example", want: PeerName{Kind: PeerNameDNS, Value: "xn--bcher-kva.example"}},
		{value: "192.0.2.1", want: PeerName{Kind: PeerNameIP, Value: "192.0.2.1"}},
		{value: "2001:DB8::1", want: PeerName{Kind: PeerNameIP, Value: "2001:db8::1"}},
		{value: "user@example.com", want: PeerName{Kind: PeerNameRFC822, Value: "user@example.com"}},
		{value: "", wantErr: true},
		{value: "*.example.com", wantErr: true},
		{value: ".example.com", wantErr: true},
		{value: "a..example.com", wantErr: true},
		{value: "https://example.com", wantErr: true},
		{value: "@example.com", wantErr: true},
		{value: "user@", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ParsePeerName(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePeerName(%q) = %v, want error", tt.value, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParsePeerName(%q) = %v, %v; want %v", tt.value, got, err, tt.want)
			}
		})
	}
}

func TestPeerNameMatches(t *testing.T) {
	certificate := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "common.example.com"},
		DNSNames:       []string{"Example.COM", "*.wild.example.com", "f*.partial.example.com", "*"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
		EmailAddresses: []string{"User@Example.com"},
	}

	tests := []struct {
		name string
		peer PeerName
		want bool
	}{
		{name: "exact DNS name ignores case", peer: PeerName{PeerNameDNS, "example.com"}, want: true},
		{name: "trailing dot", peer: PeerName{PeerNameDNS, "example.com."}, want: true},
		{name: "wildcard matches one label", peer: PeerName{PeerNameDNS, "www.wild.example.com"}, want: true},
		{name: "wildcard does not match two labels", peer: PeerName{PeerNameDNS, "a.b.wild.example.com"}},
		{name: "wildcard does not match its parent", peer: PeerName{PeerNameDNS, "wild.example.com"}},
		{name: "partial wildcard label is literal", peer: PeerName{PeerNameDNS, "foo.partial.example.com"}},
		{name: "bare wildcard matches nothing", peer: PeerName{PeerNameDNS, "localhost"}},
		{name: "common name is not consulted", peer: PeerName{PeerNameDNS, "common.example.com"}},
		{name: "IPv4 address", peer: PeerName{PeerNameIP, "192.0.2.1"}, want: true},
		{name: "IPv6 address", peer: PeerName{PeerNameIP, "2001:db8::1"}, want: true},
		{name: "other IP address", peer: PeerName{PeerNameIP, "192.0.2.2"}},
		{name: "IP address is not a DNS name", peer: PeerName{PeerNameDNS, "192.0.2.1"}},
		{name: "email domain ignores case", peer: PeerName{PeerNameRFC822, "User@example.COM"}, want: true},
		{name: "email local part is exact", peer: PeerName{PeerNameRFC822, "user@example.com"}},
		{name: "unknown kind", peer: PeerName{"URI", "https://example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PeerNameMatches(certificate, tt.peer); got != tt.want {
				t.Fatalf("PeerNameMatches(%v) = %v, want %v", tt.peer, got, tt.want)
			}
		})
	}
	if PeerNameMatches(nil, PeerName{PeerNameDNS, "example.com"}) {
		t.Fatal("nil certificate matches")
	}
	if PeerNameMatches(&x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}, PeerName{PeerNameDNS, "example.com"}) {
		t.Fatal("certificate without subjectAltName matches its common name")
	}
}
