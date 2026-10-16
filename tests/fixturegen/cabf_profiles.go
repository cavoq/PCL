package main

import (
	"crypto/x509"
	"encoding/asn1"
	"net"
	"time"
)

// cabfProfileVectors are subordinate CA certificates for each BR 7.1.2
// subordinate profile PCL infers, and for none.
func cabfProfileVectors(w vectorWriter) error {
	group, err := newCABFGroup(w, "cabf-profiles", 0x7d, "Profile")
	if err != nil {
		return err
	}
	precertificateSigning := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	for index, vector := range []struct {
		file      string
		issuedAt  time.Time
		configure func(*x509.Certificate)
	}{
		{"no-eku.pem", time.Time{}, func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"constrained-tls.pem", time.Time{}, func(c *x509.Certificate) {
			c.PermittedDNSDomainsCritical = true
			c.PermittedDNSDomains = []string{"example.com"}
			c.PermittedIPRanges = []*net.IPNet{{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)}}
		}},
		// Precertificate Signing CAs may not be issued from 2026-03-15.
		{"precertificate-signing.pem", date(2025, 6, 1, 0, 0, 0), func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{precertificateSigning}
		}},
		{"non-tls-any-eku.pem", time.Time{}, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny}
		}},
		{"non-tls-ocsp-signing.pem", time.Time{}, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageOCSPSigning}
		}},
	} {
		c, err := group.template(index, "intermediate", vector.issuedAt, []cabfPolicyInformation{cabfDVPolicy})
		if err != nil {
			return err
		}
		c.NotAfter = c.NotBefore.AddDate(5, 0, 0)
		vector.configure(c)
		if err := group.write(vector.file, c, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
