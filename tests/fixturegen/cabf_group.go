package main

import (
	"crypto"
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

// cabfDVPolicy is the CA/B Forum Domain Validated policy identifier.
var cabfDVPolicy = cabfPolicyInformation{ID: asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}}

// cabfGroup is a vector directory of CA/B Forum certificates with its own
// self-signed P-256 issuer, so one group can change without touching the
// others. Every certificate of the group certifies its subject key.
type cabfGroup struct {
	w          vectorWriter
	dir        string
	id         int64
	issuer     issued
	subjectKey crypto.Signer
}

// newCABFGroup writes the issuer of dir, "<title> Test Root", to issuer.pem.
// id numbers the group: the issuer has serial number and key identifier
// id<<8, certificate i serial number (id<<8 + 0x10 + i)<<64.
func newCABFGroup(w vectorWriter, dir string, id int64, title string) (cabfGroup, error) {
	key, err := p256Key(dir + "/issuer")
	if err != nil {
		return cabfGroup{}, err
	}
	issuer, err := issueKey(key, nil, func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(id << 8)
		c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: title + " Test Root"}
		c.NotBefore, c.NotAfter = date(2020, 1, 1, 0, 0, 0), date(2035, 1, 1, 0, 0, 0)
		ca(c, -1)
		c.SubjectKeyId = []byte{byte(id), 0x00}
		c.AuthorityKeyId = c.SubjectKeyId
	})
	if err != nil {
		return cabfGroup{}, err
	}
	if err := w.certificate(dir, "issuer.pem", issuer.cert.Raw); err != nil {
		return cabfGroup{}, err
	}
	subjectKey, err := p256Key(dir + "/subject")
	if err != nil {
		return cabfGroup{}, err
	}
	return cabfGroup{w: w, dir: dir, id: id, issuer: issuer, subjectKey: subjectKey}, nil
}

// template returns the group's certificate number index for role (see
// configureCABFPolicyRole): issued 2026-06-01, or at issuedAt when set,
// valid for 30 days, for serverAuth with digitalSignature, and with the
// certificatePolicies policies.
func (group cabfGroup) template(index int, role string, issuedAt time.Time, policies []cabfPolicyInformation) (*x509.Certificate, error) {
	policiesDER, err := asn1.Marshal(policies)
	if err != nil {
		return nil, err
	}
	c := &x509.Certificate{}
	c.SerialNumber = new(big.Int).Lsh(big.NewInt(group.id<<8+0x10+int64(index)), 64)
	c.NotBefore = date(2026, 6, 1, 0, 0, 0)
	if !issuedAt.IsZero() {
		c.NotBefore = issuedAt
	}
	c.NotAfter = c.NotBefore.Add(30 * 24 * time.Hour)
	c.KeyUsage = x509.KeyUsageDigitalSignature
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: policiesDER}}
	configureCABFPolicyRole(c, role)
	return c, nil
}

// write writes c, certifying the subject key, to file. The group's issuer
// signs it unless parent is set.
func (group cabfGroup) write(file string, c, parent *x509.Certificate, signer crypto.Signer) error {
	if parent == nil {
		parent, signer = group.issuer.cert, group.issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, c, parent, group.subjectKey.Public(), signer)
	if err != nil {
		return fmt.Errorf("%s/%s: %w", group.dir, file, err)
	}
	return group.w.certificate(group.dir, file, der)
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
