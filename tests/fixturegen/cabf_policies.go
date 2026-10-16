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

type cabfPolicyQualifier struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue
}

type cabfPolicyInformation struct {
	ID         asn1.ObjectIdentifier
	Qualifiers []cabfPolicyQualifier `asn1:"optional"`
}

// cabfPolicyVectors is independent of the other CABF chain so this group
// can be regenerated without replacing unrelated certificates and keys.
func cabfPolicyVectors(w vectorWriter) error {
	key, err := p256Key("cabf-policies/issuer")
	if err != nil {
		return err
	}
	issuer, err := issueKey(key, nil, func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(0x7500)
		c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "Policy Test Root"}
		c.NotBefore, c.NotAfter = date(2020, 1, 1, 0, 0, 0), date(2035, 1, 1, 0, 0, 0)
		ca(c, -1)
		c.SubjectKeyId = []byte{0x75, 0x00}
		c.AuthorityKeyId = c.SubjectKeyId
	})
	if err != nil {
		return err
	}
	if err := w.certificate("cabf-policies", "issuer.pem", issuer.cert.Raw); err != nil {
		return err
	}
	certKey, err := p256Key("cabf-policies/subject")
	if err != nil {
		return err
	}

	dv := cabfPolicyInformation{ID: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}}
	ev := cabfPolicyInformation{ID: asn1.ObjectIdentifier{2, 23, 140, 1, 1}}
	private := cabfPolicyInformation{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}}
	anyPolicy := cabfPolicyInformation{ID: asn1.ObjectIdentifier{2, 5, 29, 32, 0}}
	cps := func(uri string) cabfPolicyQualifier {
		return cabfPolicyQualifier{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
			Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(uri)}}
	}
	withQualifiers := func(policy cabfPolicyInformation, qualifiers ...cabfPolicyQualifier) cabfPolicyInformation {
		policy.Qualifiers = qualifiers
		return policy
	}
	notice := cabfPolicyQualifier{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2},
		Value: asn1.RawValue{FullBytes: []byte{0x30, 0x00}}}
	unknown := cabfPolicyQualifier{ID: asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}
	wrongTag := cps("https://example.com/cps")
	wrongTag.Value.Tag = asn1.TagUTF8String
	cutover := date(2023, 9, 15, 0, 0, 0)
	for index, vector := range []struct {
		name     string
		role     string
		policies []cabfPolicyInformation
		issuedAt time.Time
	}{
		{"subscriber-one-private", "leaf", []cabfPolicyInformation{dv, private}, time.Time{}},
		{"subscriber-multiple", "leaf", []cabfPolicyInformation{dv, ev}, time.Time{}},
		{"subscriber-none", "leaf", []cabfPolicyInformation{private}, time.Time{}},
		{"subscriber-private-first", "leaf", []cabfPolicyInformation{private, dv}, time.Time{}},
		{"cps-http", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("http://example.com/cps"))}, time.Time{}},
		{"cps-https", "leaf", []cabfPolicyInformation{dv, withQualifiers(private, cps("https://example.com/cps"))}, time.Time{}},
		{"qualifier-second-policy", "leaf", []cabfPolicyInformation{dv, withQualifiers(private, notice)}, time.Time{}},
		{"qualifier-second-value", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("https://example.com/cps"), notice)}, time.Time{}},
		{"qualifier-unknown", "leaf", []cabfPolicyInformation{withQualifiers(dv, unknown)}, time.Time{}},
		{"cps-ftp", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("ftp://example.com/cps"))}, time.Time{}},
		{"cps-no-host", "leaf", []cabfPolicyInformation{withQualifiers(dv, cps("https:cps"))}, time.Time{}},
		{"cps-wrong-tag", "leaf", []cabfPolicyInformation{withQualifiers(dv, wrongTag)}, time.Time{}},
		{"empty", "leaf", nil, time.Time{}},
		{"duplicate", "leaf", []cabfPolicyInformation{dv, dv}, time.Time{}},
		{"ca-any-alone", "intermediate", []cabfPolicyInformation{anyPolicy}, time.Time{}},
		{"ca-any-mixed", "intermediate", []cabfPolicyInformation{anyPolicy, dv}, time.Time{}},
		{"ca-multiple", "intermediate", []cabfPolicyInformation{dv, ev}, time.Time{}},
		{"ca-private-first", "intermediate", []cabfPolicyInformation{private, dv}, time.Time{}},
		{"ca-cps", "intermediate", []cabfPolicyInformation{withQualifiers(dv, cps("https://example.com/cps"))}, time.Time{}},
		{"non-tls-private", "nonTLS", []cabfPolicyInformation{private}, time.Time{}},
		{"responder-cps", "ocspSigning", []cabfPolicyInformation{withQualifiers(private, cps("https://example.com/cps"))}, time.Time{}},
		{"responder-unknown", "ocspSigning", []cabfPolicyInformation{withQualifiers(private, unknown)}, time.Time{}},
		{"root-any-mixed", "root", []cabfPolicyInformation{anyPolicy, dv}, time.Time{}},
		{"before-cutover", "leaf", []cabfPolicyInformation{dv, ev}, cutover.Add(-time.Second)},
		{"at-cutover", "leaf", []cabfPolicyInformation{dv, ev}, cutover},
	} {
		policiesDER, err := asn1.Marshal(vector.policies)
		if err != nil {
			return err
		}
		c := &x509.Certificate{}
		c.SerialNumber = new(big.Int).Lsh(big.NewInt(int64(0x7510+index)), 64)
		c.NotBefore = date(2026, 6, 1, 0, 0, 0)
		if !vector.issuedAt.IsZero() {
			c.NotBefore = vector.issuedAt
		}
		c.NotAfter = c.NotBefore.Add(30 * 24 * time.Hour)
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: policiesDER}}
		configureCABFPolicyRole(c, vector.role)
		parent, signer := issuer.cert, issuer.key
		if vector.role == "root" {
			parent, signer = c, certKey
		}
		// Do not round-trip through Go's parser: the duplicate-policy vector
		// is intentionally rejected there but must reach PCL's own parser.
		der, err := x509.CreateCertificate(rand.Reader, c, parent, certKey.Public(), signer)
		if err != nil {
			return fmt.Errorf("%s: %w", vector.name, err)
		}
		if err := w.certificate("cabf-policies", vector.name+".pem", der); err != nil {
			return err
		}
	}
	return nil
}

func configureCABFPolicyRole(c *x509.Certificate, role string) {
	if role == "leaf" {
		c.DNSNames = []string{"www.example.com"}
		c.OCSPServer = []string{"http://ocsp.example.com"}
		c.IssuingCertificateURL = []string{"http://ca.example.com/issuer.crt"}
		return
	}
	c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "Policy Test Certificate"}
	c.SubjectKeyId = []byte{0x75, 0x01}
	if role == "ocspSigning" {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{0x05, 0x00},
		})
		return
	}
	ca(c, -1)
	if role == "root" {
		c.NotAfter = c.NotBefore.AddDate(10, 0, 0)
		c.AuthorityKeyId = c.SubjectKeyId
		c.ExtKeyUsage = nil
		return
	}
	c.CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
	c.IssuingCertificateURL = []string{"http://ca.example.com/issuer.crt"}
	if role == "nonTLS" {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
}
