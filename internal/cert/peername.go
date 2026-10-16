package cert

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/zmap/zcrypto/x509"
)

// PeerNameKind is the subjectAltName type a reference identity is matched
// against.
type PeerNameKind string

const (
	PeerNameDNS    PeerNameKind = "DNS"
	PeerNameIP     PeerNameKind = "IP"
	PeerNameRFC822 PeerNameKind = "RFC822"
)

// PeerName is a reference identity the end-entity certificate must present:
// the DNS name, IP address or email address an application expects of its
// peer (RFC 9525).
type PeerName struct {
	Kind  PeerNameKind `json:"kind" yaml:"kind"`
	Value string       `json:"value" yaml:"value"`
}

func (name PeerName) String() string {
	return string(name.Kind) + ":" + name.Value
}

// ParsePeerName classifies a reference identity: an IP address, an email
// address when it contains "@", and otherwise a DNS name. Internationalized
// DNS names must be given in their A-label (punycode) form.
func ParsePeerName(value string) (PeerName, error) {
	if value == "" {
		return PeerName{}, errors.New("peer name is empty")
	}
	if ip := net.ParseIP(value); ip != nil {
		return PeerName{Kind: PeerNameIP, Value: ip.String()}, nil
	}
	if local, domain, ok := splitEmail(value); ok {
		if local == "" || domain == "" {
			return PeerName{}, fmt.Errorf("peer name %q is not a valid email address", value)
		}
		return PeerName{Kind: PeerNameRFC822, Value: value}, nil
	}
	dns := strings.TrimSuffix(value, ".")
	if dns == "" || strings.Contains(dns, "*") || strings.Contains(dns, "..") ||
		strings.HasPrefix(dns, ".") || strings.ContainsAny(dns, " /:") {
		return PeerName{}, fmt.Errorf("peer name %q is not a valid DNS name", value)
	}
	return PeerName{Kind: PeerNameDNS, Value: dns}, nil
}

// PeerNameMatches reports whether the certificate's subjectAltName presents
// the reference identity. Following RFC 9525, the subject common name is not
// consulted, and a wildcard is honored only as the complete leftmost label of
// a dNSName, matching exactly one label.
func PeerNameMatches(certificate *x509.Certificate, name PeerName) bool {
	if certificate == nil {
		return false
	}
	switch name.Kind {
	case PeerNameDNS:
		reference := strings.ToLower(strings.TrimSuffix(name.Value, "."))
		for _, presented := range certificate.DNSNames {
			if dnsNameMatches(strings.ToLower(presented), reference) {
				return true
			}
		}
	case PeerNameIP:
		reference := net.ParseIP(name.Value)
		for _, presented := range certificate.IPAddresses {
			if reference != nil && reference.Equal(presented) {
				return true
			}
		}
	case PeerNameRFC822:
		for _, presented := range certificate.EmailAddresses {
			if emailMatches(presented, name.Value) {
				return true
			}
		}
	}
	return false
}

func dnsNameMatches(presented, reference string) bool {
	if presented == reference {
		return true
	}
	suffix, wildcard := strings.CutPrefix(presented, "*.")
	if !wildcard || suffix == "" || strings.Contains(suffix, "*") {
		return false
	}
	label, rest, found := strings.Cut(reference, ".")
	return found && label != "" && rest == suffix
}

// emailMatches compares the local part exactly and the domain without regard
// to case (RFC 5280 4.2.1.6, 7.5).
func emailMatches(presented, reference string) bool {
	presentedLocal, presentedDomain, ok := splitEmail(presented)
	if !ok {
		return false
	}
	referenceLocal, referenceDomain, ok := splitEmail(reference)
	return ok && presentedLocal == referenceLocal && strings.EqualFold(presentedDomain, referenceDomain)
}

func splitEmail(value string) (string, string, bool) {
	index := strings.LastIndex(value, "@")
	if index < 0 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}
