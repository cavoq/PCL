package cert

import (
	"net"
	"net/url"
	"strings"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/zmap/zcrypto/x509"
)

// NameConstraintsValid applies the currently supported Name Constraints
// subset to one certificate in an already ordered leaf-to-root chain. DNS,
// rfc822Name, URI-host, and IP SAN constraints are supported; directoryName,
// registeredID, otherName, x400Address, ediPartyName, and complete Section 7
// name comparison remain outside this bounded profile check.
func NameConstraintsValid(current *Info, chain []*Info) bool {
	if current == nil || current.Cert == nil || len(chain) == 0 {
		return false
	}
	position, ok := certificatePosition(current, chain)
	if !ok {
		return false
	}
	// Section 6.1.4 does not apply issuer name constraints to a self-issued
	// certificate unless that certificate is the final target (position zero
	// in PCL's leaf-to-root ordering). Its own constraints remain available
	// when certificates below it are evaluated.
	if position > 0 && IsSelfIssued(current.Cert) {
		return true
	}

	// RFC 5280 Section 6.1.4(g): permitted subtrees are intersected
	// across the chain (each CA can only narrow), while excluded subtrees
	// are unioned.
	var excluded nameConstraints
	var permittedSets []nameConstraints
	for index := len(chain) - 1; index > position; index-- {
		issuer := chain[index]
		if issuer == nil || issuer.Cert == nil {
			return false
		}
		if permitted := extractPermittedNameConstraints(issuer.Cert); !permitted.empty() {
			permittedSets = append(permittedSets, permitted)
		}
		excluded = excluded.merge(extractExcludedNameConstraints(issuer.Cert))
	}

	certificate := current.Cert
	emailAddresses := certificate.EmailAddresses
	if !certificateHasExtension(certificate, oid.SubjectAlternativeName) {
		// RFC 5280 requires rfc822Name constraints to cover legacy
		// emailAddress attributes in the subject DN when SAN is absent.
		emailAddresses = append([]string(nil), certificate.Subject.EmailAddress...)
	}
	if !checkDNSNames(certificate.DNSNames, nil, excluded.dns) ||
		!checkEmails(emailAddresses, nil, excluded.emails) ||
		!checkURIs(certificate.URIs, nil, excluded.uris) ||
		!checkIPs(certificate.IPAddresses, nil, excluded.ips) {
		return false
	}

	for _, permitted := range permittedSets {
		if !checkDNSNames(certificate.DNSNames, permitted.dns, nil) ||
			!checkEmails(emailAddresses, permitted.emails, nil) ||
			!checkURIs(certificate.URIs, permitted.uris, nil) ||
			!checkIPs(certificate.IPAddresses, permitted.ips, nil) {
			return false
		}
	}
	return true
}

type nameConstraints struct {
	dns    []string
	emails []string
	uris   []string
	ips    []net.IPNet
}

func (constraints nameConstraints) empty() bool {
	return len(constraints.dns) == 0 && len(constraints.emails) == 0 &&
		len(constraints.uris) == 0 && len(constraints.ips) == 0
}

func (constraints nameConstraints) merge(other nameConstraints) nameConstraints {
	return nameConstraints{
		dns:    append(constraints.dns, other.dns...),
		emails: append(constraints.emails, other.emails...),
		uris:   append(constraints.uris, other.uris...),
		ips:    append(constraints.ips, other.ips...),
	}
}

func extractPermittedNameConstraints(certificate *x509.Certificate) nameConstraints {
	constraints := nameConstraints{}
	for _, value := range certificate.PermittedDNSNames {
		constraints.dns = append(constraints.dns, value.Data)
	}
	for _, value := range certificate.PermittedEmailAddresses {
		constraints.emails = append(constraints.emails, value.Data)
	}
	for _, value := range certificate.PermittedURIs {
		constraints.uris = append(constraints.uris, value.Data)
	}
	for _, value := range certificate.PermittedIPAddresses {
		constraints.ips = append(constraints.ips, value.Data)
	}
	return constraints
}

func extractExcludedNameConstraints(certificate *x509.Certificate) nameConstraints {
	constraints := nameConstraints{}
	for _, value := range certificate.ExcludedDNSNames {
		constraints.dns = append(constraints.dns, value.Data)
	}
	for _, value := range certificate.ExcludedEmailAddresses {
		constraints.emails = append(constraints.emails, value.Data)
	}
	for _, value := range certificate.ExcludedURIs {
		constraints.uris = append(constraints.uris, value.Data)
	}
	for _, value := range certificate.ExcludedIPAddresses {
		constraints.ips = append(constraints.ips, value.Data)
	}
	return constraints
}

func checkDNSNames(names, permitted, excluded []string) bool {
	for _, name := range names {
		if !matchesDNSConstraint(name, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesDNSConstraint(name string, permitted, excluded []string) bool {
	name = strings.ToLower(name)
	for _, constraint := range excluded {
		if matchesDNS(name, strings.ToLower(constraint)) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, constraint := range permitted {
		if matchesDNS(name, strings.ToLower(constraint)) {
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

func checkEmails(emails, permitted, excluded []string) bool {
	for _, email := range emails {
		if !matchesEmailConstraint(email, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesEmailConstraint(email string, permitted, excluded []string) bool {
	for _, constraint := range excluded {
		if matchesEmail(email, constraint) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, constraint := range permitted {
		if matchesEmail(email, constraint) {
			return true
		}
	}
	return false
}

func matchesEmail(email, constraint string) bool {
	if constraint == "" {
		return true
	}
	emailAt := strings.LastIndex(email, "@")
	if emailAt < 0 {
		return false
	}
	constraintAt := strings.LastIndex(constraint, "@")
	if constraintAt >= 0 {
		return email[:emailAt] == constraint[:constraintAt] &&
			strings.EqualFold(email[emailAt+1:], constraint[constraintAt+1:])
	}
	return matchesHostConstraint(
		strings.ToLower(email[emailAt+1:]),
		strings.ToLower(constraint),
	)
}

func checkURIs(uris, permitted, excluded []string) bool {
	for _, uri := range uris {
		if !matchesURIConstraint(uri, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesURIConstraint(uri string, permitted, excluded []string) bool {
	if len(permitted) == 0 && len(excluded) == 0 {
		return true
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if !validFullyQualifiedDNSName(host) {
		return false
	}
	for _, constraint := range excluded {
		if matchesHostConstraint(host, strings.ToLower(constraint)) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, constraint := range permitted {
		if matchesHostConstraint(host, strings.ToLower(constraint)) {
			return true
		}
	}
	return false
}

func matchesHostConstraint(host, constraint string) bool {
	if constraint == "" {
		return true
	}
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(host, constraint)
	}
	return host == constraint
}

func validFullyQualifiedDNSName(host string) bool {
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func checkIPs(addresses []net.IP, permitted, excluded []net.IPNet) bool {
	for _, address := range addresses {
		if !matchesIPConstraint(address, permitted, excluded) {
			return false
		}
	}
	return true
}

func matchesIPConstraint(address net.IP, permitted, excluded []net.IPNet) bool {
	for _, constraint := range excluded {
		if constraint.Contains(address) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, constraint := range permitted {
		if constraint.Contains(address) {
			return true
		}
	}
	return false
}
