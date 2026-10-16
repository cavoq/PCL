package cert

import (
	"net"
	"net/url"
	"strings"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509ext"
)

// NameConstraintsValid applies the supported Name Constraints forms to one
// certificate in an already ordered leaf-to-root chain. DNS, rfc822Name,
// URI-host, IP, and directoryName constraints are supported. registeredID,
// otherName, x400Address, and ediPartyName remain outside this bounded check.
func NameConstraintsValid(current *Info, chain []*Info) bool {
	if current == nil || current.Cert == nil || len(chain) == 0 {
		return false
	}
	position, ok := ChainIndex(current, chain)
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
		permitted, issuerExcluded, valid := extractNameConstraints(issuer.Cert)
		if !valid {
			return false
		}
		if !permitted.empty() {
			permittedSets = append(permittedSets, permitted)
		}
		excluded = excluded.merge(issuerExcluded)
	}

	certificate := current.Cert
	subjectAlternativeName := certificateExtension(certificate, oid.SubjectAlternativeName)
	if subjectAlternativeName.Present() && !subjectAlternativeName.Unique() {
		return false
	}
	emailAddresses := certificate.EmailAddresses
	if !subjectAlternativeName.Present() {
		// RFC 5280 requires rfc822Name constraints to cover legacy
		// emailAddress attributes in the subject DN when SAN is absent.
		emailAddresses = append([]string(nil), certificate.Subject.EmailAddress...)
	}
	directoryNames := certificateDirectoryNames(certificate)
	if !checkDNSNames(certificate.DNSNames, nil, excluded.dns) ||
		!checkEmails(emailAddresses, nil, excluded.emails) ||
		!checkURIs(certificate.URIs, nil, excluded.uris) ||
		!checkIPs(certificate.IPAddresses, nil, excluded.ips) ||
		!checkDirectoryNames(directoryNames, nil, excluded.directoryNames) {
		return false
	}

	for _, permitted := range permittedSets {
		if !checkDNSNames(certificate.DNSNames, permitted.dns, nil) ||
			!checkEmails(emailAddresses, permitted.emails, nil) ||
			!checkURIs(certificate.URIs, permitted.uris, nil) ||
			!checkIPs(certificate.IPAddresses, permitted.ips, nil) ||
			!checkDirectoryNames(directoryNames, permitted.directoryNames, nil) {
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
	// directoryNames are DER-encoded Names of directoryName subtrees.
	directoryNames [][]byte
}

func (constraints nameConstraints) empty() bool {
	return len(constraints.dns) == 0 && len(constraints.emails) == 0 &&
		len(constraints.uris) == 0 && len(constraints.ips) == 0 && len(constraints.directoryNames) == 0
}

func (constraints nameConstraints) merge(other nameConstraints) nameConstraints {
	return nameConstraints{
		dns:            append(constraints.dns, other.dns...),
		emails:         append(constraints.emails, other.emails...),
		uris:           append(constraints.uris, other.uris...),
		ips:            append(constraints.ips, other.ips...),
		directoryNames: append(constraints.directoryNames, other.directoryNames...),
	}
}

// directoryNameSubtrees returns the directoryName bases in subtrees.
func directoryNameSubtrees(subtrees []x509ext.NameConstraintSubtreeFacts) [][]byte {
	var bases [][]byte
	for _, subtree := range subtrees {
		if subtree.BaseTag == 4 {
			bases = append(bases, subtree.BaseRawValue)
		}
	}
	return bases
}

// certificateDirectoryNames returns the names that directoryName constraints
// apply to: a non-empty subject and every directoryName subject alternative
// name (RFC 5280 4.2.1.10).
func certificateDirectoryNames(certificate *x509.Certificate) [][]byte {
	var names [][]byte
	if subject, err := x509asn1.ParseDistinguishedNameStrict(certificate.RawSubject); err == nil && len(subject.RDNs) > 0 {
		names = append(names, certificate.RawSubject)
	}
	match := certificateExtension(certificate, oid.SubjectAlternativeName)
	if extension, unique := match.Extension(); unique {
		if alternatives, err := x509ext.DecodeGeneralNames(extension.Value); err == nil {
			for _, alternative := range alternatives {
				if alternative.Tag == 4 {
					names = append(names, alternative.RawValue)
				}
			}
		}
	}
	return names
}

// checkDirectoryNames requires every name to be outside all excluded subtrees
// and, when permitted subtrees exist, within at least one of them.
func checkDirectoryNames(names, permitted, excluded [][]byte) bool {
	for _, name := range names {
		for _, base := range excluded {
			if x509asn1.NameWithinSubtree(name, base) {
				return false
			}
		}
		if len(permitted) == 0 {
			continue
		}
		within := false
		for _, base := range permitted {
			if x509asn1.NameWithinSubtree(name, base) {
				within = true
				break
			}
		}
		if !within {
			return false
		}
	}
	return true
}

func extractNameConstraints(certificate *x509.Certificate) (nameConstraints, nameConstraints, bool) {
	var permittedDirectoryNames, excludedDirectoryNames [][]byte
	match := certificateExtension(certificate, oid.NameConstraints)
	if match.Present() {
		extension, unique := match.Extension()
		if !unique {
			return nameConstraints{}, nameConstraints{}, false
		}
		facts, err := x509ext.DecodeNameConstraintsStrict(extension.Value)
		if err != nil {
			return nameConstraints{}, nameConstraints{}, false
		}
		permittedDirectoryNames = directoryNameSubtrees(facts.PermittedSubtrees)
		excludedDirectoryNames = directoryNameSubtrees(facts.ExcludedSubtrees)
	}

	permitted := nameConstraints{directoryNames: permittedDirectoryNames}
	for _, value := range certificate.PermittedDNSNames {
		if !validDNSNameConstraint(value.Data) {
			return nameConstraints{}, nameConstraints{}, false
		}
		permitted.dns = append(permitted.dns, value.Data)
	}
	for _, value := range certificate.PermittedEmailAddresses {
		permitted.emails = append(permitted.emails, value.Data)
	}
	for _, value := range certificate.PermittedURIs {
		permitted.uris = append(permitted.uris, value.Data)
	}
	for _, value := range certificate.PermittedIPAddresses {
		permitted.ips = append(permitted.ips, value.Data)
	}

	excluded := nameConstraints{directoryNames: excludedDirectoryNames}
	for _, value := range certificate.ExcludedDNSNames {
		if !validDNSNameConstraint(value.Data) {
			return nameConstraints{}, nameConstraints{}, false
		}
		excluded.dns = append(excluded.dns, value.Data)
	}
	for _, value := range certificate.ExcludedEmailAddresses {
		excluded.emails = append(excluded.emails, value.Data)
	}
	for _, value := range certificate.ExcludedURIs {
		excluded.uris = append(excluded.uris, value.Data)
	}
	for _, value := range certificate.ExcludedIPAddresses {
		excluded.ips = append(excluded.ips, value.Data)
	}
	return permitted, excluded, true
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
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

// validDNSNameConstraint applies the dNSName subtree syntax that the strict
// Name Constraints decoder enforces to the typed constraint fields.
func validDNSNameConstraint(constraint string) bool {
	return x509ext.ValidDNSNameConstraint(constraint)
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
