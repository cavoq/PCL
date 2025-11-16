package utils

import "crypto/x509"

func GetSubjectNames(cert *x509.Certificate) []string {
	var names []string

	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}

	// Add SAN DNS names (important for leaf certs)
	if len(cert.DNSNames) > 0 {
		names = append(names, cert.DNSNames...)
	}

	return names
}

func GetIssuerNames(cert *x509.Certificate) []string {
	var names []string

	if cert.Issuer.CommonName != "" {
		names = append(names, cert.Issuer.CommonName)
	}

	return names
}
