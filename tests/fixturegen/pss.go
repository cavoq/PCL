package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Algorithm identifiers for the RFC 4055 vectors. Each hash identifier
// carries NULL parameters.
var (
	oidRSASSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	sha1Identifier   = algorithmIdentifier(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, []byte{0x05, 0x00})
	sha256Identifier = algorithmIdentifier(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, []byte{0x05, 0x00})
	sha384Identifier = algorithmIdentifier(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, []byte{0x05, 0x00})
)

func algorithmIdentifier(oid asn1.ObjectIdentifier, params []byte) []byte {
	encoded, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return sequence(append(encoded, params...))
}

// pssParameters encodes RSASSA-PSS-params from its explicitly tagged fields;
// a nil field is omitted.
func pssParameters(hash, maskGen []byte, saltLength, trailerField int) []byte {
	var content []byte
	if hash != nil {
		content = append(content, element(0xa0, hash)...)
	}
	if maskGen != nil {
		content = append(content, element(0xa1, maskGen)...)
	}
	if saltLength >= 0 {
		content = append(content, element(0xa2, []byte{0x02, 0x01, byte(saltLength)})...)
	}
	if trailerField >= 0 {
		content = append(content, element(0xa3, []byte{0x02, 0x01, byte(trailerField)})...)
	}
	return sequence(content)
}

func mgf1(hash []byte) []byte { return algorithmIdentifier(oidMGF1, hash) }

// pssCertificate issues a self-signed end entity whose TBS and outer
// signature algorithm is algorithm and signs it with RSASSA-PSS over hash
// with saltLength. A non-nil spki replaces the subject public key
// AlgorithmIdentifier. When algorithm names an MGF1 hash other than hash
// the signature does not verify; the vectors test parameter encoding only.
func pssCertificate(configure func(*x509.Certificate), algorithm, spki []byte, hash crypto.Hash, saltLength int) ([]byte, error) {
	if configure == nil {
		configure = func(*x509.Certificate) {}
	}
	certificate, err := vectorEndEntity(configure)
	if err != nil {
		return nil, err
	}
	der, err := rewriteTBSCertificate(certificate.cert.Raw, func(fields [][]byte) ([][]byte, error) {
		fields[2] = algorithm
		if spki != nil {
			var info struct {
				Algorithm asn1.RawValue
				Key       asn1.RawValue
			}
			if _, err := asn1.Unmarshal(fields[6], &info); err != nil {
				return nil, fmt.Errorf("decode subjectPublicKeyInfo: %w", err)
			}
			fields[6] = sequence(append(bytes.Clone(spki), info.Key.FullBytes...))
		}
		return fields, nil
	})
	if err != nil {
		return nil, err
	}
	envelope, err := decodeSignedEnvelope(der)
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	digest.Write(envelope.TBS.FullBytes)
	key, ok := certificate.key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PSS vector needs an RSA key")
	}
	signature, err := rsa.SignPSS(rand.Reader, key, hash, digest.Sum(nil), &rsa.PSSOptions{SaltLength: saltLength})
	if err != nil {
		return nil, err
	}
	bitString, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: len(signature) * 8})
	if err != nil {
		return nil, err
	}
	content := append(bytes.Clone(envelope.TBS.FullBytes), algorithm...)
	return sequence(append(content, bitString...)), nil
}

// rfc4055Vectors are certificates whose RSASSA-PSS parameters or
// RSASSA-PSS/RSAES-OAEP key usage break, or follow, RFC 4055.
func rfc4055Vectors(w vectorWriter) error {
	sha256PSS := algorithmIdentifier(oidRSASSAPSS, pssParameters(sha256Identifier, mgf1(sha256Identifier), 32, -1))
	keyUsage := func(usage x509.KeyUsage) func(*x509.Certificate) {
		return func(template *x509.Certificate) { template.KeyUsage = usage }
	}
	vectors := []struct {
		name       string
		configure  func(*x509.Certificate)
		algorithm  []byte
		spki       []byte
		hash       crypto.Hash
		saltLength int
	}{
		// SHA-256, MGF1 with SHA-256, a 32-octet salt: every rule passes.
		{"certificate-pss-sha256", nil, sha256PSS, nil, crypto.SHA256, 32},
		// The SHA-1 defaults spelled out, which signers must omit.
		{"certificate-pss-explicit-defaults", nil,
			algorithmIdentifier(oidRSASSAPSS, pssParameters(sha1Identifier, mgf1(sha1Identifier), 20, 1)), nil, crypto.SHA1, 20},
		// No RSASSA-PSS-params in a signature algorithm identifier.
		{"certificate-pss-missing-parameters", nil, algorithmIdentifier(oidRSASSAPSS, nil), nil, crypto.SHA1, 20},
		// MGF1 over SHA-384 with a SHA-256 message hash.
		{"certificate-pss-mgf-hash-differs", nil,
			algorithmIdentifier(oidRSASSAPSS, pssParameters(sha256Identifier, mgf1(sha384Identifier), 32, -1)), nil, crypto.SHA256, 32},
		// An end-entity RSASSA-PSS key whose keyUsage lacks both signature bits.
		{"certificate-pss-key-encipherment-only", keyUsage(x509.KeyUsageKeyEncipherment),
			sha256PSS, algorithmIdentifier(oidRSASSAPSS, nil), crypto.SHA256, 32},
		// An RSAES-OAEP key that may also sign.
		{"certificate-oaep-key-digital-signature", keyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
			sha256PSS, algorithmIdentifier(oidRSAESOAEP, nil), crypto.SHA256, 32},
		// An RSAES-OAEP key with both encipherment bits.
		{"certificate-oaep-key-both-encipherments", keyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment),
			sha256PSS, algorithmIdentifier(oidRSAESOAEP, nil), crypto.SHA256, 32},
	}
	for _, vector := range vectors {
		der, err := pssCertificate(vector.configure, vector.algorithm, vector.spki, vector.hash, vector.saltLength)
		if err != nil {
			return fmt.Errorf("%s: %w", vector.name, err)
		}
		if err := w.certificate(vector.name, "certificate.pem", der); err != nil {
			return err
		}
	}
	return nil
}
