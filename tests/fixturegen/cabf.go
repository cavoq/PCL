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
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"
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
	rootTemplate := func(change func(*x509.Certificate)) func(*x509.Certificate) {
		return func(template *x509.Certificate) {
			template.SerialNumber = big.NewInt(0x7401)
			template.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "PCL BR Root"}
			template.NotBefore, template.NotAfter = date(2026, 1, 1, 0, 0, 0), date(2036, 1, 1, 0, 0, 0)
			ca(template, -1)
			template.SubjectKeyId = []byte{0x74, 0x01}
			template.AuthorityKeyId = template.SubjectKeyId
			if change != nil {
				change(template)
			}
		}
	}
	root, err := issueKey(rootKey, nil, rootTemplate(nil))
	if err != nil {
		return err
	}
	intermediateKey, err := p256Key()
	if err != nil {
		return err
	}
	dvPolicy := asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	ovPolicy := asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	// A TLS Subordinate CA (7.1.2.6); change adjusts it.
	subordinate := func(change func(*x509.Certificate)) func(*x509.Certificate) {
		return func(template *x509.Certificate) {
			template.SerialNumber = big.NewInt(0x7402)
			template.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "PCL BR Issuing CA"}
			template.NotBefore, template.NotAfter = date(2026, 1, 1, 0, 0, 0), date(2031, 1, 1, 0, 0, 0)
			ca(template, 0)
			template.KeyUsage |= x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			template.Policies = []x509.OID{mustOID(dvPolicy)}
			template.CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
			template.IssuingCertificateURL = []string{"http://ca.example.com/root.crt"}
			if change != nil {
				change(template)
			}
		}
	}
	intermediate, err := issueKey(intermediateKey, &root, subordinate(nil))
	if err != nil {
		return err
	}

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
	return cabfCAVectors(w, root, intermediate, rootTemplate, subordinate, issuedAt)
}

// cabfCAVectors writes the CA, OCSP responder, OCSP response and CRL
// vectors: conforming ones under cabf-conformant and one vector per group
// of violations.
func cabfCAVectors(w vectorWriter, root, intermediate issued, rootTemplate, subordinate func(func(*x509.Certificate)) func(*x509.Certificate), issuedAt time.Time) error {
	// A root valid for 30 years, with an EKU and an organizational unit.
	badRootKey, err := p256Key()
	if err != nil {
		return err
	}
	badRoot, err := issueKey(badRootKey, nil, rootTemplate(func(template *x509.Certificate) {
		template.NotAfter = date(2056, 1, 1, 0, 0, 0)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.Subject.OrganizationalUnit = []string{"Roots"}
	}))
	if err != nil {
		return err
	}
	// A TLS subordinate with codeSigning, keyEncipherment, an OU, and
	// neither policies nor CRL distribution points.
	badSubordinateKey, err := p256Key()
	if err != nil {
		return err
	}
	badSubordinate, err := issueKey(badSubordinateKey, &root, subordinate(func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning}
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
		template.Subject.OrganizationalUnit = []string{"Issuing"}
		template.Policies = nil
		template.CRLDistributionPoints = nil
	}))
	if err != nil {
		return err
	}

	noCheck := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{0x05, 0x00}}
	responderTemplate := func(serial int64, change func(*x509.Certificate)) func(*x509.Certificate) {
		return func(template *x509.Certificate) {
			template.SerialNumber = big.NewInt(serial)
			template.Subject = pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Test"}, CommonName: "PCL BR OCSP Responder"}
			template.NotBefore, template.NotAfter = date(2026, 1, 1, 0, 0, 0), date(2027, 1, 1, 0, 0, 0)
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
			template.SubjectKeyId = []byte{byte(serial >> 8), byte(serial)}
			template.ExtraExtensions = []pkix.Extension{noCheck}
			if change != nil {
				change(template)
			}
		}
	}
	responderKey, err := p256Key()
	if err != nil {
		return err
	}
	responder, err := issueKey(responderKey, &intermediate, responderTemplate(0x7421, nil))
	if err != nil {
		return err
	}
	// A responder with forbidden usages, noncanonical basic constraints, a SAN, a CRL
	// distribution point, caIssuers AIA and no id-pkix-ocsp-nocheck.
	badResponder, err := issueKey(responderKey, &intermediate, responderTemplate(0x7422, func(template *x509.Certificate) {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		template.DNSNames = []string{"ocsp.example.com"}
		template.CRLDistributionPoints = []string{"http://crl.example.com/issuing.crl"}
		template.IssuingCertificateURL = []string{"http://ca.example.com/issuing.crt"}
		// cA FALSE must be omitted, not explicitly encoded. Keep the semantic
		// cA value false so this remains classified as an OCSP signing cert.
		template.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0x00},
		}}
	}))
	if err != nil {
		return err
	}

	leaf, err := readVectorLeaf(w, "cabf-conformant")
	if err != nil {
		return err
	}
	response := func(responder issued, embed bool, algorithm x509.SignatureAlgorithm, change func(*ocsp.Response)) ([]byte, error) {
		template := ocsp.Response{
			Status:             ocsp.Good,
			SerialNumber:       leaf.SerialNumber,
			ThisUpdate:         issuedAt,
			NextUpdate:         issuedAt.Add(4 * 24 * time.Hour),
			SignatureAlgorithm: algorithm,
		}
		if embed {
			template.Certificate = responder.cert
		}
		if change != nil {
			change(&template)
		}
		return ocsp.CreateResponse(intermediate.cert, responder.cert, template, responder.key)
	}
	goodResponse, err := response(responder, true, 0, nil)
	if err != nil {
		return err
	}
	badResponse, err := response(badResponder, true, 0, nil)
	if err != nil {
		return err
	}
	// A response signed with ecdsa-with-SHA1, which 7.1.3.2 does not permit.
	sha1Response, err := response(intermediate, false, x509.ECDSAWithSHA1, nil)
	if err != nil {
		return err
	}

	// General key requirements must also apply to the extracted signing cert.
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Deliberately weak negative test vector.
	if err != nil {
		return err
	}
	weakResponder, err := issueKey(weakKey, &intermediate, responderTemplate(0x7423, nil))
	if err != nil {
		return err
	}
	weakResponse, err := response(weakResponder, true, 0, nil)
	if err != nil {
		return err
	}
	reasonExtensionResponse, err := response(responder, true, 0, func(template *ocsp.Response) {
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: []byte{0x0a, 0x01, 0x04}}}
	})
	if err != nil {
		return err
	}
	holdResponse, err := response(responder, true, 0, func(template *ocsp.Response) {
		template.Status, template.RevocationReason = ocsp.Revoked, ocsp.CertificateHold
		template.RevokedAt = issuedAt.Add(-time.Hour)
	})
	if err != nil {
		return err
	}

	// A cross-certified CA may retain an older subject with an OU. The pack
	// cannot infer the selected profile or the historical compliance evidence.
	cross, err := issueKey(intermediate.key, &root, subordinate(func(template *x509.Certificate) {
		template.Subject.Country = nil
		template.Subject.OrganizationalUnit = []string{"Legacy CA"}
	}))
	if err != nil {
		return err
	}
	// Non-TLS constrained subordinates may use private policies instead of a
	// Reserved Certificate Policy Identifier (7.1.2.3.2).
	nonTLS, err := issueKey(intermediate.key, &root, subordinate(func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		template.Policies = []x509.OID{mustOID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1})}
	}))
	if err != nil {
		return err
	}

	return firstError(
		w.certificate("cabf-root-bad", "root.pem", badRoot.cert.Raw),
		w.certificate("cabf-subordinate-bad", "intermediate.pem", badSubordinate.cert.Raw),
		w.certificate("cabf-cross-subject", "intermediate.pem", cross.cert.Raw),
		w.certificate("cabf-non-tls-subordinate", "intermediate.pem", nonTLS.cert.Raw),
		w.certificate("cabf-conformant", "responder.pem", responder.cert.Raw),
		w.f.write(filepath.Join("vectors", "cabf-conformant", "leaf.ocsp"), goodResponse),
		w.f.write(filepath.Join("vectors", "cabf-ocsp-bad-responder", "leaf.ocsp"), badResponse),
		w.f.write(filepath.Join("vectors", "cabf-ocsp-sha1", "leaf.ocsp"), sha1Response),
		w.f.write(filepath.Join("vectors", "cabf-ocsp-weak-key", "leaf.ocsp"), weakResponse),
		w.f.write(filepath.Join("vectors", "cabf-ocsp-reason-extension", "leaf.ocsp"), reasonExtensionResponse),
		w.f.write(filepath.Join("vectors", "cabf-ocsp-hold", "leaf.ocsp"), holdResponse),
		cabfCRLVectors(w, root, intermediate, issuedAt),
	)
}

func cabfCRLVectors(w vectorWriter, root, intermediate issued, issuedAt time.Time) error {
	idp := func(scope byte, name bool) pkix.Extension {
		var content []byte
		if name {
			content = element(0xa0, element(0xa0, element(0x86, []byte("http://crl.example.com/issuing.crl"))))
		}
		content = append(content, scope, 0x01, 0xff)
		return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: sequence(content)}
	}
	revocationList := func(issuer issued, window time.Duration, extensions []pkix.Extension, entries []x509.RevocationListEntry) ([]byte, error) {
		return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    big.NewInt(7),
			ThisUpdate:                issuedAt,
			NextUpdate:                issuedAt.Add(window),
			ExtraExtensions:           extensions,
			RevokedCertificateEntries: entries,
		}, issuer.cert, issuer.key)
	}
	day := 24 * time.Hour
	goodCRL, err := revocationList(intermediate, 7*day, []pkix.Extension{idp(0x81, true)},
		[]x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: issuedAt.Add(-day), ReasonCode: 4}})
	if err != nil {
		return err
	}
	// A user-certificate CRL valid 11 days with a certificateHold entry.
	badCRL, err := revocationList(intermediate, 11*day, []pkix.Extension{idp(0x81, true)},
		[]x509.RevocationListEntry{{SerialNumber: big.NewInt(98), RevocationTime: issuedAt.Add(-day), ReasonCode: 6}})
	if err != nil {
		return err
	}
	longRootCRL, err := revocationList(root, 400*day, nil, nil)
	if err != nil {
		return err
	}
	unnamedCRL, err := revocationList(intermediate, 7*day, []pkix.Extension{idp(0x81, false)}, nil)
	if err != nil {
		return err
	}
	attributeCRL, err := revocationList(intermediate, 7*day, []pkix.Extension{idp(0x85, true)}, nil)
	if err != nil {
		return err
	}

	return firstError(
		w.f.write(filepath.Join("vectors", "cabf-conformant", "intermediate.crl"), goodCRL),
		w.f.write(filepath.Join("vectors", "cabf-crl-bad", "intermediate.crl"), badCRL),
		w.f.write(filepath.Join("vectors", "cabf-crl-bad", "root.crl"), longRootCRL),
		w.f.write(filepath.Join("vectors", "cabf-crl-bad", "unnamed.crl"), unnamedCRL),
		w.f.write(filepath.Join("vectors", "cabf-crl-bad", "attribute.crl"), attributeCRL),
	)
}

// readVectorLeaf parses the leaf.pem the vector directory was given.
func readVectorLeaf(w vectorWriter, vector string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(w.f.dir, "vectors", vector, "leaf.pem"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM leaf", vector)
	}
	return x509.ParseCertificate(block.Bytes)
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
