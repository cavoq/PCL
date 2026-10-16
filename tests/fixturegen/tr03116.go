package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"path/filepath"
)

// issueKey issues a certificate for key, letting Go choose the signature
// algorithm from the signer's key: ecdsa-with-SHA256 under a P-256 CA.
func issueKey(key crypto.Signer, issuer *issued, configure func(template *x509.Certificate)) (issued, error) {
	template := &x509.Certificate{}
	configure(template)
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		return issued{}, fmt.Errorf("certificate %x: %w", template.SerialNumber, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return issued{}, err
	}
	return issued{cert: certificate, key: key}, nil
}

func p256Key() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// tr03116Vectors writes, under tests/vectors, a TR-03116-4 conforming
// ECDSA P-256 chain with CRLs (tr03116-conformant) and variants that each
// break or exercise one requirement: a root valid for seven years, a leaf
// without ExtendedKeyUsage, and leaves with 3000-bit and 2048-bit RSA keys.
func tr03116Vectors(w vectorWriter) error {
	notBefore := date(2026, 1, 1, 0, 0, 0)
	revocation := func(template *x509.Certificate) {
		template.CRLDistributionPoints = []string{"http://crl.example.test/tr03116.crl"}
		template.OCSPServer = []string{"http://ocsp.example.test"}
	}
	rootKey, err := p256Key()
	if err != nil {
		return err
	}
	root, err := issueKey(rootKey, nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x7301)
		template.Subject.CommonName = "TR-03116 Root CA"
		template.NotBefore, template.NotAfter = notBefore, notBefore.AddDate(6, 0, -1)
		ca(template, 1)
		revocation(template)
	})
	if err != nil {
		return err
	}
	intermediateKey, err := p256Key()
	if err != nil {
		return err
	}
	intermediate, err := issueKey(intermediateKey, &root, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x7302)
		template.Subject.CommonName = "TR-03116 Intermediate CA"
		template.NotBefore, template.NotAfter = notBefore, notBefore.AddDate(5, 0, -1)
		ca(template, 0)
		revocation(template)
	})
	if err != nil {
		return err
	}
	leafTemplate := func(serial int64, eku bool) func(*x509.Certificate) {
		return func(template *x509.Certificate) {
			template.SerialNumber = big.NewInt(serial)
			template.Subject.CommonName = "tr03116.example.test"
			template.DNSNames = []string{"tr03116.example.test"}
			template.NotBefore, template.NotAfter = notBefore, notBefore.AddDate(3, 0, -1)
			template.KeyUsage = x509.KeyUsageDigitalSignature
			if eku {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
			revocation(template)
		}
	}
	leafKey, err := p256Key()
	if err != nil {
		return err
	}
	leaf, err := issueKey(leafKey, &intermediate, leafTemplate(0x7303, true))
	if err != nil {
		return err
	}
	crls := func(vector string) error {
		for _, list := range []struct {
			file   string
			issuer issued
		}{{"root.crl", root}, {"intermediate.crl", intermediate}} {
			der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: date(2026, 5, 1, 0, 0, 0),
				NextUpdate: date(2026, 7, 1, 0, 0, 0),
			}, list.issuer.cert, list.issuer.key)
			if err != nil {
				return err
			}
			if err := w.f.write(filepath.Join("vectors", vector, list.file), der); err != nil {
				return err
			}
		}
		return nil
	}
	chain := func(vector string, leaf issued) error {
		return firstError(w.certificate(vector, "leaf.pem", leaf.cert.Raw),
			w.certificate(vector, "intermediate.pem", intermediate.cert.Raw),
			w.certificate(vector, "root.pem", root.cert.Raw), crls(vector))
	}
	if err := chain("tr03116-conformant", leaf); err != nil {
		return err
	}

	withoutEKU, err := issueKey(leafKey, &intermediate, leafTemplate(0x7304, false))
	if err != nil {
		return err
	}
	if err := chain("tr03116-leaf-without-eku", withoutEKU); err != nil {
		return err
	}
	for _, bits := range []int{3000, 2048} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return err
		}
		rsaLeaf, err := issueKey(key, &intermediate, leafTemplate(int64(0x7300+bits), true))
		if err != nil {
			return err
		}
		if err := chain(fmt.Sprintf("tr03116-leaf-rsa-%d", bits), rsaLeaf); err != nil {
			return err
		}
	}

	longRoot, err := issueKey(rootKey, nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x7305)
		template.Subject.CommonName = "TR-03116 Root CA"
		template.NotBefore, template.NotAfter = notBefore, notBefore.AddDate(7, 0, 0)
		ca(template, 1)
		revocation(template)
	})
	if err != nil {
		return err
	}
	return w.certificate("tr03116-root-seven-years", "root.pem", longRoot.cert.Raw)
}
