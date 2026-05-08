package operator

import (
	"net"
	"net/url"
	"strings"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/node"
)

type NameConstraintsValid struct{}

func (NameConstraintsValid) Name() string { return "nameConstraintsValid" }

func (NameConstraintsValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCert() || !ctx.HasChain() {
		return false, nil
	}

	pos := ctx.Cert.Position
	cert := ctx.Cert.Cert

	// RFC 5280 §6.1.4(g): permitted subtrees are intersected across the chain
	// (each CA can only narrow, never expand); excluded subtrees are unioned.
	var excluded nameConstraints
	var permittedSets []nameConstraints

	for i := len(ctx.Chain) - 1; i > pos; i-- {
		ca := ctx.Chain[i]
		if ca.Cert == nil {
			continue
		}
		if perm := extractPermitted(ca.Cert); !perm.empty() {
			permittedSets = append(permittedSets, perm)
		}
		excluded = excluded.merge(extractExcluded(ca.Cert))
	}

	// Exclusions: union — if any CA excludes a name, it is excluded.
	if !checkDNSNames(cert.DNSNames, nil, excluded.dns) {
		return false, nil
	}
	if !checkEmails(cert.EmailAddresses, nil, excluded.emails) {
		return false, nil
	}
	if !checkURIs(cert.URIs, nil, excluded.uris) {
		return false, nil
	}
	if !checkIPs(cert.IPAddresses, nil, excluded.ips) {
		return false, nil
	}

	// Permitted: intersection — every CA's permitted set must independently be satisfied.
	for _, permitted := range permittedSets {
		if !checkDNSNames(cert.DNSNames, permitted.dns, nil) {
			return false, nil
		}
		if !checkEmails(cert.EmailAddresses, permitted.emails, nil) {
			return false, nil
		}
		if !checkURIs(cert.URIs, permitted.uris, nil) {
			return false, nil
		}
		if !checkIPs(cert.IPAddresses, permitted.ips, nil) {
			return false, nil
		}
	}

	return true, nil
}

type nameConstraints struct {
	dns    []string
	emails []string
	uris   []string
	ips    []net.IPNet
}

func (nc nameConstraints) empty() bool {
	return len(nc.dns) == 0 && len(nc.emails) == 0 && len(nc.uris) == 0 && len(nc.ips) == 0
}

func (nc nameConstraints) merge(other nameConstraints) nameConstraints {
	return nameConstraints{
		dns:    append(nc.dns, other.dns...),
		emails: append(nc.emails, other.emails...),
		uris:   append(nc.uris, other.uris...),
		ips:    append(nc.ips, other.ips...),
	}
}

func extractPermitted(cert *x509.Certificate) nameConstraints {
	nc := nameConstraints{}
	for _, v := range cert.PermittedDNSNames {
		nc.dns = append(nc.dns, v.Data)
	}
	for _, v := range cert.PermittedEmailAddresses {
		nc.emails = append(nc.emails, v.Data)
	}
	for _, v := range cert.PermittedURIs {
		nc.uris = append(nc.uris, v.Data)
	}
	for _, v := range cert.PermittedIPAddresses {
		nc.ips = append(nc.ips, v.Data)
	}
	return nc
}

func extractExcluded(cert *x509.Certificate) nameConstraints {
	nc := nameConstraints{}
	for _, v := range cert.ExcludedDNSNames {
		nc.dns = append(nc.dns, v.Data)
	}
	for _, v := range cert.ExcludedEmailAddresses {
		nc.emails = append(nc.emails, v.Data)
	}
	for _, v := range cert.ExcludedURIs {
		nc.uris = append(nc.uris, v.Data)
	}
	for _, v := range cert.ExcludedIPAddresses {
		nc.ips = append(nc.ips, v.Data)
	}
	return nc
}

func checkDNSNames(names []string, permitted, excluded []string) bool {
	for _, name := range names {
		if !matchesDNSConstraint(name, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesDNSConstraint(name string, permitted, excluded []string) bool {
	name = strings.ToLower(name)

	for _, exc := range excluded {
		if matchesDNS(name, strings.ToLower(exc)) {
			return false
		}
	}

	if len(permitted) == 0 {
		return true
	}

	for _, perm := range permitted {
		if matchesDNS(name, strings.ToLower(perm)) {
			return true
		}
	}
	return false
}

func matchesDNS(name, constraint string) bool {
	if constraint == "" {
		return true
	}
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(name, constraint)
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

func checkEmails(emails []string, permitted, excluded []string) bool {
	for _, email := range emails {
		if !matchesEmailConstraint(email, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesEmailConstraint(email string, permitted, excluded []string) bool {
	email = strings.ToLower(email)

	for _, exc := range excluded {
		if matchesEmail(email, strings.ToLower(exc)) {
			return false
		}
	}

	if len(permitted) == 0 {
		return true
	}

	for _, perm := range permitted {
		if matchesEmail(email, strings.ToLower(perm)) {
			return true
		}
	}
	return false
}

func matchesEmail(email, constraint string) bool {
	if constraint == "" {
		return true
	}

	atIdx := strings.LastIndex(email, "@")
	if atIdx < 0 {
		return false
	}
	domain := email[atIdx+1:]

	if strings.Contains(constraint, "@") {
		return email == constraint
	}

	return matchesDNS(domain, constraint)
}

func checkURIs(uris []string, permitted, excluded []string) bool {
	for _, uri := range uris {
		if !matchesURIConstraint(uri, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesURIConstraint(uri string, permitted, excluded []string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())

	for _, exc := range excluded {
		if matchesDNS(host, strings.ToLower(exc)) {
			return false
		}
	}

	if len(permitted) == 0 {
		return true
	}

	for _, perm := range permitted {
		if matchesDNS(host, strings.ToLower(perm)) {
			return true
		}
	}
	return false
}

func checkIPs(ips []net.IP, permitted, excluded []net.IPNet) bool {
	for _, ip := range ips {
		if !matchesIPConstraint(ip, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesIPConstraint(ip net.IP, permitted, excluded []net.IPNet) bool {
	for _, exc := range excluded {
		if exc.Contains(ip) {
			return false
		}
	}

	if len(permitted) == 0 {
		return true
	}

	for _, perm := range permitted {
		if perm.Contains(ip) {
			return true
		}
	}
	return false
}
