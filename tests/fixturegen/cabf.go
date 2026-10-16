package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"time"
)

// cabfVectors writes CA/B Forum Baseline Requirements vectors under
// tests/vectors: a conforming Domain Validated chain (cabf-conformant) and
// subscriber certificates under the same intermediate that each break a
// group of requirements. The subscribers are issued 2026-06-01, when the
// maximum Validity Period is 200 days.
func cabfVectors(w vectorWriter) error {
	issuedAt := date(2026, 6, 1, 0, 0, 0)
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	root, err := issueKey(rootKey, nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x7401)
		template.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "PCL BR Root"}
		template.NotBefore, template.NotAfter = date(2026, 1, 1, 0, 0, 0), date(2036, 1, 1, 0, 0, 0)
		ca(template, 1)
	})
	if err != nil {
		return err
	}
	intermediateKey, err := p256Key()
	if err != nil {
		return err
	}
	intermediate, err := issueKey(intermediateKey, &root, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x7402)
		template.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "PCL BR Issuing CA"}
		template.NotBefore, template.NotAfter = date(2026, 1, 1, 0, 0, 0), date(2031, 1, 1, 0, 0, 0)
		ca(template, 0)
		template.CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
		template.IssuingCertificateURL = []string{"http://ca.example.com/root.crt"}
	})
	if err != nil {
		return err
	}

	dvPolicy := asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	ovPolicy := asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	// subscriber is a conforming DV subscriber template; change adjusts it.
	subscriber := func(serial int64, change func(*x509.Certificate)) func(*x509.Certificate) {
		return func(template *x509.Certificate) {
			template.SerialNumber = new(big.Int).Lsh(big.NewInt(serial), 64)
			template.DNSNames = []string{"www.example.com"}
			template.NotBefore = issuedAt
			template.NotAfter = issuedAt.Add(180 * 24 * time.Hour)
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.Policies = []x509.OID{mustOID(dvPolicy)}
			template.OCSPServer = []string{"http://ocsp.example.com"}
			template.IssuingCertificateURL = []string{"http://ca.example.com/issuing.crt"}
			if change != nil {
				change(template)
			}
		}
	}
	write := func(name string, key crypto.Signer, configure func(*x509.Certificate)) error {
		if key == nil {
			var err error
			if key, err = p256Key(); err != nil {
				return err
			}
		}
		leaf, err := issueKey(key, &intermediate, configure)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return w.certificate(name, "leaf.pem", leaf.cert.Raw)
	}
	if err := firstError(w.certificate("cabf-conformant", "root.pem", root.cert.Raw),
		w.certificate("cabf-conformant", "intermediate.pem", intermediate.cert.Raw)); err != nil {
		return err
	}
	rsa2049, err := rsa.GenerateKey(rand.Reader, 2049)
	if err != nil {
		return err
	}
	vectors := []struct {
		name   string
		key    crypto.Signer
		change func(*x509.Certificate)
	}{
		{"cabf-conformant", nil, nil},
		// 200 days inclusive of notAfter: the maximum, above the 199-day
		// recommendation.
		{"cabf-validity-200-days", nil, func(template *x509.Certificate) {
			template.NotAfter = issuedAt.Add(200*24*time.Hour - time.Second)
		}},
		// One second more than 200 days.
		{"cabf-validity-over-200-days", nil, func(template *x509.Certificate) {
			template.NotAfter = issuedAt.Add(200 * 24 * time.Hour)
		}},
		// Each name breaks one SAN rule.
		{"cabf-bad-names", nil, func(template *x509.Certificate) {
			template.DNSNames = []string{"www.example.com", "server.internal", "1.2.0.192.in-addr.arpa", "ab--cd.example.com", "example.com."}
			template.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
		}},
		// An ECC key with keyEncipherment, codeSigning, and no policies.
		{"cabf-bad-usages", nil, func(template *x509.Certificate) {
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning}
			template.Policies = nil
		}},
		// OV without organizationName or locality, with an OU, and a
		// commonName that is not a SAN value.
		{"cabf-ov-incomplete", nil, func(template *x509.Certificate) {
			template.Policies = []x509.OID{mustOID(ovPolicy)}
			template.Subject = pkix.Name{Country: []string{"DE"}, OrganizationalUnit: []string{"Web"}, CommonName: "other.example.com"}
		}},
		// A 2049-bit RSA modulus, not divisible by 8.
		{"cabf-rsa-2049", rsa2049, func(template *x509.Certificate) {
			template.KeyUsage = x509.KeyUsageDigitalSignature
		}},
	}
	for index, vector := range vectors {
		if err := write(vector.name, vector.key, subscriber(int64(0x7410+index), vector.change)); err != nil {
			return err
		}
	}
	return nil
}

func mustOID(identifier asn1.ObjectIdentifier) x509.OID {
	oid, err := x509.OIDFromInts(toUint64(identifier))
	if err != nil {
		panic(err)
	}
	return oid
}

func toUint64(identifier asn1.ObjectIdentifier) []uint64 {
	out := make([]uint64, len(identifier))
	for index, arc := range identifier {
		out[index] = uint64(arc)
	}
	return out
}
