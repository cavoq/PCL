package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// cabfWildcardVectors are subscriber certificates whose only SAN is a
// Wildcard Domain Name, for BR 3.2.2.6. They have their own issuer so the
// group can be regenerated alone.
func cabfWildcardVectors(w vectorWriter) error {
	key, err := p256Key()
	if err != nil {
		return err
	}
	issuer, err := issueKey(key, nil, func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(0x7c00)
		c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "Wildcard Test Root"}
		c.NotBefore, c.NotAfter = date(2020, 1, 1, 0, 0, 0), date(2035, 1, 1, 0, 0, 0)
		ca(c, -1)
		c.SubjectKeyId = []byte{0x7c, 0x00}
		c.AuthorityKeyId = c.SubjectKeyId
	})
	if err != nil {
		return err
	}
	if err := w.certificate("cabf-wildcard", "issuer.pem", issuer.cert.Raw); err != nil {
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
	for index, vector := range []struct{ file, name string }{
		{"registrable-domain.pem", "*.example.com"},
		{"icann-suffix.pem", "*.com"},
		{"multi-label-icann-suffix.pem", "*.co.uk"},
		{"private-suffix.pem", "*.github.io"},
	} {
		c := &x509.Certificate{}
		c.SerialNumber = new(big.Int).Lsh(big.NewInt(int64(0x7c10+index)), 64)
		c.NotBefore = date(2026, 6, 1, 0, 0, 0)
		c.NotAfter = c.NotBefore.Add(30 * 24 * time.Hour)
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: policiesDER}}
		configureCABFPolicyRole(c, "leaf")
		c.DNSNames = []string{vector.name}
		der, err := x509.CreateCertificate(rand.Reader, c, issuer.cert, certKey.Public(), issuer.key)
		if err != nil {
			return fmt.Errorf("%s: %w", vector.file, err)
		}
		if err := w.certificate("cabf-wildcard", vector.file, der); err != nil {
			return err
		}
	}
	return nil
}
