package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"path/filepath"
	"time"
)

// cabfAKIVectors exercise the authorityKeyIdentifier field profile of BR
// 7.1.2.11.1 and 7.1.2.1.3 for certificates and CRLs. Like
// cabfPolicyVectors they have their own issuer and can be regenerated alone.
func cabfAKIVectors(w vectorWriter) error {
	key, err := p256Key()
	if err != nil {
		return err
	}
	issuerKeyID := []byte{0x7a, 0x00}
	issuer, err := issueKey(key, nil, func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(0x7a00)
		c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "AKI Test Root"}
		c.NotBefore, c.NotAfter = date(2020, 1, 1, 0, 0, 0), date(2035, 1, 1, 0, 0, 0)
		ca(c, -1)
		c.SubjectKeyId = issuerKeyID
		c.AuthorityKeyId = c.SubjectKeyId
	})
	if err != nil {
		return err
	}
	if err := w.certificate("cabf-aki", "issuer.pem", issuer.cert.Raw); err != nil {
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

	// akiValue encodes AuthorityKeyIdentifier with the fields requested;
	// authorityCertIssuer names the issuer as a directoryName.
	akiValue := func(keyID []byte, withIssuer, withSerial bool) []byte {
		var content []byte
		if keyID != nil {
			content = append(content, element(0x80, keyID)...)
		}
		if withIssuer {
			content = append(content, element(0xa1, element(0xa4, issuer.cert.RawSubject))...)
		}
		if withSerial {
			content = append(content, element(0x82, issuer.cert.SerialNumber.Bytes())...)
		}
		return sequence(content)
	}
	aki := func(value []byte, critical bool) *pkix.Extension {
		return &pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: critical, Value: value}
	}
	cutover := date(2023, 9, 15, 0, 0, 0)
	for index, vector := range []struct {
		name     string
		role     string
		aki      *pkix.Extension // nil: Go's keyIdentifier-only AKI
		omitAKI  bool
		issuedAt time.Time
	}{
		{name: "leaf-key-identifier-only", role: "leaf"},
		{name: "leaf-issuer-and-serial", role: "leaf", aki: aki(akiValue(issuerKeyID, true, true), false)},
		{name: "leaf-no-key-identifier", role: "leaf", aki: aki(akiValue(nil, true, true), false)},
		{name: "leaf-critical", role: "leaf", aki: aki(akiValue(issuerKeyID, false, false), true)},
		{name: "leaf-issuer-without-serial", role: "leaf", aki: aki(akiValue(issuerKeyID, true, false), false)},
		{name: "leaf-missing", role: "leaf", omitAKI: true},
		{name: "leaf-before-cutover", role: "leaf", aki: aki(akiValue(issuerKeyID, true, true), false),
			issuedAt: cutover.Add(-time.Second)},
		{name: "intermediate-issuer-and-serial", role: "intermediate", aki: aki(akiValue(issuerKeyID, true, true), false)},
		{name: "intermediate-missing", role: "intermediate", omitAKI: true},
		{name: "root-issuer-and-serial", role: "root"},
	} {
		c := &x509.Certificate{}
		c.SerialNumber = new(big.Int).Lsh(big.NewInt(int64(0x7a10+index)), 64)
		c.NotBefore = date(2026, 6, 1, 0, 0, 0)
		if !vector.issuedAt.IsZero() {
			c.NotBefore = vector.issuedAt
		}
		c.NotAfter = c.NotBefore.Add(30 * 24 * time.Hour)
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 32}, Value: policiesDER}}
		configureCABFPolicyRole(c, vector.role)
		parent, signer := *issuer.cert, issuer.key
		if vector.role == "root" {
			// A root's AKI names itself; its serial and subject are known
			// before signing, so the forbidden fields can refer to it.
			c.SubjectKeyId = []byte{0x7a, 0x01}
			c.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "AKI Test Self-Signed Root"}
			subject, err := asn1.Marshal(c.Subject.ToRDNSequence())
			if err != nil {
				return err
			}
			c.ExtraExtensions = append(c.ExtraExtensions[:0], *aki(sequence(append(append(
				element(0x80, c.SubjectKeyId),
				element(0xa1, element(0xa4, subject))...),
				element(0x82, c.SerialNumber.Bytes())...)), false))
			parent, signer = *c, certKey
		} else if vector.aki != nil {
			c.ExtraExtensions = append(c.ExtraExtensions, *vector.aki)
		}
		if vector.omitAKI {
			// Go derives the AKI from the parent's subjectKeyIdentifier.
			parent.SubjectKeyId = nil
		}
		der, err := x509.CreateCertificate(rand.Reader, c, &parent, certKey.Public(), signer)
		if err != nil {
			return fmt.Errorf("%s: %w", vector.name, err)
		}
		if err := w.certificate("cabf-aki", vector.name+".pem", der); err != nil {
			return err
		}
	}

	thisUpdate := date(2026, 6, 1, 0, 0, 0)
	list, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(7 * 24 * time.Hour),
	}, issuer.cert, issuer.key)
	if err != nil {
		return err
	}
	issuerAndSerial, err := rewriteCRLExtension(list, issuer.key, aki(akiValue(issuerKeyID, true, true), false))
	if err != nil {
		return err
	}
	missing, err := rewriteCRLExtension(list, issuer.key, nil)
	if err != nil {
		return err
	}
	return firstError(
		w.f.write(filepath.Join("vectors", "cabf-aki", "key-identifier-only.crl"), list),
		w.f.write(filepath.Join("vectors", "cabf-aki", "issuer-and-serial.crl"), issuerAndSerial),
		w.f.write(filepath.Join("vectors", "cabf-aki", "missing.crl"), missing),
	)
}

// rewriteCRLExtension replaces the CRL's authorityKeyIdentifier with aki, or
// removes it when aki is nil, and signs the CRL again with key. Go's
// CreateRevocationList always writes its own keyIdentifier-only AKI.
func rewriteCRLExtension(der []byte, key crypto.Signer, aki *pkix.Extension) ([]byte, error) {
	envelope, err := decodeSignedEnvelope(der)
	if err != nil {
		return nil, err
	}
	var tbs struct {
		Raw                 asn1.RawContent
		Version             int `asn1:"optional,default:0"`
		Signature           pkix.AlgorithmIdentifier
		Issuer              asn1.RawValue
		ThisUpdate          time.Time
		NextUpdate          time.Time                 `asn1:"optional"`
		RevokedCertificates []pkix.RevokedCertificate `asn1:"optional"`
		Extensions          []pkix.Extension          `asn1:"tag:0,optional,explicit"`
	}
	if rest, err := asn1.Unmarshal(envelope.TBS.FullBytes, &tbs); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("decode TBSCertList: rest=%x err=%w", rest, err)
	}
	extensions := tbs.Extensions[:0]
	for _, extension := range tbs.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) {
			extensions = append(extensions, extension)
		} else if aki != nil {
			extensions = append(extensions, *aki)
		}
	}
	tbs.Raw, tbs.Extensions = nil, extensions
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	content := append(bytes.Clone(tbsDER), envelope.Algorithm.FullBytes...)
	return resign(sequence(append(content, envelope.Signature.FullBytes...)), key)
}
