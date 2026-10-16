package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"time"
)

// cabfProfileVectors are subordinate CA certificates for each BR 7.1.2
// subordinate profile PCL infers, and for none. They have their own issuer
// so the group can be regenerated alone.
func cabfProfileVectors(w vectorWriter) error {
	key, err := p256Key()
	if err != nil {
		return err
	}
	issuer, err := issueKey(key, nil, func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(0x7d00)
		c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "Profile Test Root"}
		c.NotBefore, c.NotAfter = date(2020, 1, 1, 0, 0, 0), date(2035, 1, 1, 0, 0, 0)
		ca(c, -1)
		c.SubjectKeyId = []byte{0x7d, 0x00}
		c.AuthorityKeyId = c.SubjectKeyId
	})
	if err != nil {
		return err
	}
	if err := w.certificate("cabf-profiles", "issuer.pem", issuer.cert.Raw); err != nil {
		return err
	}
	certKey, err := p256Key()
	if err != nil {
		return err
	}
	policiesDER, err := asn1.Marshal([]cabfPolicyInformation{{ID: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}}})
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
		c := &x509.Certificate{}
		c.SerialNumber = new(big.Int).Lsh(big.NewInt(int64(0x7d10+index)), 64)
		c.NotBefore = date(2026, 6, 1, 0, 0, 0)
		if !vector.issuedAt.IsZero() {
			c.NotBefore = vector.issuedAt
		}
		c.NotAfter = c.NotBefore.AddDate(5, 0, 0)
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: policiesDER}}
		configureCABFPolicyRole(c, "intermediate")
		vector.configure(c)
		der, err := x509.CreateCertificate(rand.Reader, c, issuer.cert, certKey.Public(), issuer.key)
		if err != nil {
			return fmt.Errorf("%s: %w", vector.file, err)
		}
		if err := w.certificate("cabf-profiles", vector.file, der); err != nil {
			return err
		}
	}
	return nil
}
