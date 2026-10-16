// Command fixturegen writes the certificate, CRL and OCSP fixtures under
// tests/certs, tests/crls and tests/ocsps, and the DER vectors under
// tests/vectors. Run it from the repository root
// with `make fixtures`. Keys are new on every run, so every fixture is
// rewritten; their names, extensions, validity windows and serial numbers
// are fixed here. Private keys are never written.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 5280 4.2.1.2 method (1) key identifier
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"
)

func main() {
	dir := "tests"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := generate(dir); err != nil {
		log.Fatal(err)
	}
}

// issued is a certificate with the key that signs for it.
type issued struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type fixtures struct {
	dir string
}

func generate(dir string) error {
	f := fixtures{dir: dir}
	for _, step := range []func() error{f.bsiChain, f.crlSignatureChain, f.ocspChain, f.nameConstraintsChain, f.vectors} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func date(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// bsiChain writes root.pem, intermediate.pem, leaf.pem and chain.pem, an
// RFC 5280 profile chain with OpenSSL-style UTF8String names, CRL
// distribution points and AIA, and crls/revoked-leaf.crl, which revokes the
// leaf, with a copy whose signature does not verify.
func (f fixtures) bsiChain() error {
	dp := []string{"http://crl.example.test/bsi.crl"}
	aia := func(template *x509.Certificate) {
		template.CRLDistributionPoints = dp
		template.OCSPServer = []string{"http://ocsp.example.test"}
		template.IssuingCertificateURL = []string{"http://crt.example.test/issuer.crt"}
	}
	name := func(unit, common string) []byte {
		return utf8Name([][2]string{
			{"C", "DE"}, {"ST", "Berlin"}, {"L", "Berlin"}, {"O", "ExampleOrg"}, {"OU", unit}, {"CN", common},
		})
	}
	// The CAs carry RSA-4096 keys, the leaf RSA-2048.
	root, err := issueRSA(4096, nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x6a1e)
		template.RawSubject = name("Root", "BSI Root CA")
		template.NotBefore, template.NotAfter = date(2025, 12, 20, 12, 45, 54), date(2031, 12, 19, 12, 45, 54)
		ca(template, 2)
		aia(template)
	})
	if err != nil {
		return err
	}
	intermediate, err := issueRSA(4096, &root, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x46ec)
		template.RawSubject = name("Intermediate", "BSI Intermediate CA")
		template.NotBefore, template.NotAfter = date(2025, 12, 20, 12, 45, 55), date(2030, 12, 19, 12, 45, 55)
		ca(template, 1)
		aia(template)
	})
	if err != nil {
		return err
	}
	leaf, err := issue(&intermediate, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x609e)
		template.RawSubject = name("Leaf", "leaf.example.test")
		template.NotBefore, template.NotAfter = date(2025, 12, 20, 12, 45, 55), date(2028, 3, 24, 12, 45, 55)
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"leaf.example.test"}
		endEntityWithNoncriticalBasicConstraints(template)
		aia(template)
	}, withSubjectKeyID)
	if err != nil {
		return err
	}
	if err := f.writeCerts("root.pem", root); err != nil {
		return err
	}
	if err := f.writeCerts("intermediate.pem", intermediate); err != nil {
		return err
	}
	if err := f.writeCerts("leaf.pem", leaf); err != nil {
		return err
	}
	if err := f.writeCerts("chain.pem", leaf, intermediate, root); err != nil {
		return err
	}
	revocations := func() *x509.RevocationList {
		return &x509.RevocationList{
			Number:     big.NewInt(42),
			ThisUpdate: date(2026, 1, 10, 0, 0, 0),
			NextUpdate: date(2030, 1, 10, 0, 0, 0),
			RevokedCertificateEntries: []x509.RevocationListEntry{{
				SerialNumber:   leaf.cert.SerialNumber,
				RevocationTime: date(2026, 1, 10, 0, 0, 0),
			}},
		}
	}
	if err := f.writeCRL("revoked-leaf.crl", intermediate, revocations()); err != nil {
		return err
	}
	// The same CRL under the intermediate's name and key identifier, signed
	// by another key.
	impostor, err := issue(nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x46ed)
		template.RawSubject = intermediate.cert.RawSubject
		template.SubjectKeyId = intermediate.cert.SubjectKeyId
		template.NotBefore, template.NotAfter = intermediate.cert.NotBefore, intermediate.cert.NotAfter
		ca(template, -1)
	})
	if err != nil {
		return err
	}
	return f.writeCRL("revoked-leaf-wrong-signature.crl", impostor, revocations())
}

// crlSignatureChain writes crl-signature-{root,intermediate,leaf}.pem and
// crls/crl-signature-intermediate.crl, an empty CRL from the intermediate.
func (f fixtures) crlSignatureChain() error {
	name := func(common string) pkix.Name {
		return pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Integration"}, CommonName: common}
	}
	root, err := issue(nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(1001)
		template.Subject = name("PCL Test Root CA")
		template.SubjectKeyId = []byte{0x10, 0x01}
		template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2036, 1, 10, 0, 0, 0)
		ca(template, -1)
	})
	if err != nil {
		return err
	}
	intermediate, err := issue(&root, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(1002)
		template.Subject = name("PCL Test Intermediate CA")
		template.SubjectKeyId = []byte{0x20, 0x02}
		template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2031, 1, 10, 0, 0, 0)
		ca(template, -1)
	})
	if err != nil {
		return err
	}
	leaf, err := issue(&intermediate, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(1003)
		template.Subject = name("crl-signature.leaf.example.test")
		template.NotBefore, template.NotAfter = date(2025, 12, 10, 0, 0, 0), date(2027, 1, 10, 0, 0, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.BasicConstraintsValid = true
		template.DNSNames = []string{"crl-signature.leaf.example.test"}
	})
	if err != nil {
		return err
	}
	for file, certificate := range map[string]issued{
		"crl-signature-root.pem":         root,
		"crl-signature-intermediate.pem": intermediate,
		"crl-signature-leaf.pem":         leaf,
	} {
		if err := f.writeCerts(file, certificate); err != nil {
			return err
		}
	}
	return f.writeCRL("crl-signature-intermediate.crl", intermediate, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: date(2026, 1, 10, 0, 0, 0),
		NextUpdate: date(2027, 1, 10, 0, 0, 0),
	})
}

// ocspChain writes ocsp-{root,intermediate,leaf}.pem and the OCSP responses
// under ocsps/, all signed by the intermediate unless stated otherwise.
func (f fixtures) ocspChain() error {
	name := func(common string) pkix.Name {
		return pkix.Name{Country: []string{"DE"}, Organization: []string{"PCL Integration"}, CommonName: common}
	}
	root, err := issue(nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(2001)
		template.Subject = name("PCL OCSP Root CA")
		template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2036, 1, 10, 0, 0, 0)
		ca(template, 1)
	})
	if err != nil {
		return err
	}
	intermediate, err := issue(&root, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(2002)
		template.Subject = name("PCL OCSP Intermediate CA")
		template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2034, 1, 10, 0, 0, 0)
		ca(template, -1)
		template.KeyUsage |= x509.KeyUsageDigitalSignature
	})
	if err != nil {
		return err
	}
	leaf, err := issue(&intermediate, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(2003)
		template.Subject = name("ocsp.leaf.example.test")
		template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2028, 1, 10, 0, 0, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.OCSPServer = []string{"http://ocsp.example.test"}
		template.DNSNames = []string{"ocsp.leaf.example.test"}
	})
	if err != nil {
		return err
	}
	unauthorized, err := issue(nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(2099)
		template.Subject = name("Unauthorized OCSP Responder")
		template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2036, 1, 10, 0, 0, 0)
		ca(template, -1)
	})
	if err != nil {
		return err
	}
	// Delegated responders issued by the intermediate: one whose
	// id-pkix-ocsp-nocheck is non-critical NULL (RFC 6960 4.2.2.2.1), and one
	// whose nocheck is critical and an empty OCTET STRING instead of NULL.
	delegatedResponder := func(serial int64, common string, noCheck pkix.Extension) (issued, error) {
		return issue(&intermediate, func(template *x509.Certificate) {
			template.SerialNumber = big.NewInt(serial)
			template.Subject = name(common)
			template.NotBefore, template.NotAfter = date(2025, 1, 10, 0, 0, 0), date(2030, 1, 10, 0, 0, 0)
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
			template.ExtraExtensions = []pkix.Extension{noCheck}
		})
	}
	oidOCSPNoCheck := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	delegated, err := delegatedResponder(2005, "PCL Delegated OCSP Responder",
		pkix.Extension{Id: oidOCSPNoCheck, Value: []byte{0x05, 0x00}})
	if err != nil {
		return err
	}
	badNoCheck, err := delegatedResponder(2006, "PCL Delegated OCSP Responder Bad nocheck",
		pkix.Extension{Id: oidOCSPNoCheck, Critical: true, Value: []byte{0x04, 0x00}})
	if err != nil {
		return err
	}
	for file, certificate := range map[string]issued{
		"ocsp-root.pem":         root,
		"ocsp-intermediate.pem": intermediate,
		"ocsp-leaf.pem":         leaf,
	} {
		if err := f.writeCerts(file, certificate); err != nil {
			return err
		}
	}

	current := func(status int) ocsp.Response {
		return ocsp.Response{
			Status:       status,
			SerialNumber: leaf.cert.SerialNumber,
			ProducedAt:   date(2026, 5, 8, 20, 11, 0),
			ThisUpdate:   date(2026, 1, 10, 0, 0, 0),
			NextUpdate:   date(2030, 1, 10, 0, 0, 0),
		}
	}
	revoked := current(ocsp.Revoked)
	revoked.RevokedAt, revoked.RevocationReason = date(2026, 1, 9, 0, 0, 0), ocsp.KeyCompromise
	stale := current(ocsp.Good)
	stale.ThisUpdate, stale.NextUpdate = date(2024, 1, 10, 0, 0, 0), date(2025, 1, 10, 0, 0, 0)
	noNextUpdate := current(ocsp.Good)
	noNextUpdate.NextUpdate = time.Time{}
	wrongLeaf := current(ocsp.Good)
	wrongLeaf.SerialNumber = big.NewInt(2004)

	embedding := func(template ocsp.Response, responder issued) ocsp.Response {
		template.Certificate = responder.cert
		return template
	}
	responses := []struct {
		file      string
		issuer    issued // CertID issuer
		responder issued
		template  ocsp.Response
	}{
		{"good-leaf.ocsp", intermediate, intermediate, current(ocsp.Good)},
		{"revoked-leaf.ocsp", intermediate, intermediate, revoked},
		{"unknown-leaf.ocsp", intermediate, intermediate, current(ocsp.Unknown)},
		{"stale-leaf.ocsp", intermediate, intermediate, stale},
		{"no-next-update-leaf.ocsp", intermediate, intermediate, noNextUpdate},
		{"wrong-leaf.ocsp", intermediate, intermediate, wrongLeaf},
		{"issuer-mismatch-leaf.ocsp", root, intermediate, current(ocsp.Good)},
		{"wrong-signer-leaf.ocsp", intermediate, unauthorized, current(ocsp.Good)},
		{"mixed-good-revoked/a-good-leaf.ocsp", intermediate, intermediate, current(ocsp.Good)},
		{"mixed-good-revoked/z-revoked-leaf.ocsp", intermediate, intermediate, revoked},
		{"mixed-stale-good/a-stale-leaf.ocsp", intermediate, intermediate, stale},
		{"mixed-stale-good/z-good-leaf.ocsp", intermediate, intermediate, current(ocsp.Good)},
		{"delegated-leaf.ocsp", intermediate, delegated, embedding(current(ocsp.Good), delegated)},
		{"delegated-bad-nocheck-leaf.ocsp", intermediate, badNoCheck, embedding(current(ocsp.Good), badNoCheck)},
	}
	for _, response := range responses {
		der, err := ocsp.CreateResponse(response.issuer.cert, response.responder.cert, response.template, response.responder.key)
		if err != nil {
			return fmt.Errorf("OCSP response %s: %w", response.file, err)
		}
		if err := f.write(filepath.Join("ocsps", response.file), der); err != nil {
			return err
		}
	}

	// A 33-octet response nonce, longer than RFC 8954 2.1 permits.
	der, err := ocsp.CreateResponse(intermediate.cert, intermediate.cert, current(ocsp.Good), intermediate.key)
	if err != nil {
		return err
	}
	if der, err = withResponseNonce(der, bytes.Repeat([]byte{0x5a}, 33), intermediate.key); err != nil {
		return err
	}
	return f.write(filepath.Join("ocsps", "nonce-too-long-leaf.ocsp"), der)
}

// withResponseNonce adds a Nonce responseExtension to the DER OCSP response
// der, which must have none, and signs it again with key using
// sha256WithRSAEncryption. golang.org/x/crypto/ocsp cannot create response
// extensions.
func withResponseNonce(der, nonce []byte, key crypto.Signer) ([]byte, error) {
	var response struct {
		Status        asn1.Enumerated
		ResponseBytes struct {
			Type     asn1.ObjectIdentifier
			Response []byte
		} `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &response); err != nil {
		return nil, fmt.Errorf("decode OCSP response: %w", err)
	}
	var basic struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
		Certs     asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(response.ResponseBytes.Response, &basic); err != nil {
		return nil, fmt.Errorf("decode BasicOCSPResponse: %w", err)
	}
	value, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, err
	}
	extensions, err := asn1.Marshal([]pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}, Value: value}})
	if err != nil {
		return nil, err
	}
	explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: extensions})
	if err != nil {
		return nil, err
	}
	tbs := sequence(append(bytes.Clone(basic.TBS.Bytes), explicit...))
	digest := sha256.Sum256(tbs)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	signatureBits, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)})
	if err != nil {
		return nil, err
	}
	content := append(append(tbs, basic.Algorithm.FullBytes...), signatureBits...)
	if len(basic.Certs.FullBytes) > 0 {
		content = append(content, basic.Certs.FullBytes...)
	}
	response.ResponseBytes.Response = sequence(content)
	return asn1.Marshal(response)
}

// nameConstraintsChain writes nc-root.pem, which permits example.test,
// nc-intermediate.pem, and a leaf inside (nc-good) and outside (nc-bad) the
// permitted subtree.
func (f fixtures) nameConstraintsChain() error {
	root, err := issue(nil, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x5dd7)
		template.RawSubject = utf8Name([][2]string{{"CN", "NC Test Root CA"}})
		template.NotBefore, template.NotAfter = date(2026, 5, 8, 21, 12, 21), date(2036, 5, 5, 21, 12, 21)
		ca(template, -1)
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = []string{"example.test"}
	})
	if err != nil {
		return err
	}
	intermediate, err := issue(&root, func(template *x509.Certificate) {
		template.SerialNumber = big.NewInt(0x4a64)
		template.RawSubject = utf8Name([][2]string{{"CN", "NC Test Intermediate CA"}})
		template.NotBefore, template.NotAfter = date(2026, 5, 8, 21, 12, 21), date(2031, 5, 7, 21, 12, 21)
		ca(template, -1)
		template.KeyUsage = x509.KeyUsageCertSign
	})
	if err != nil {
		return err
	}
	leaf := func(serial int64, dnsName string) (issued, error) {
		return issue(&intermediate, func(template *x509.Certificate) {
			template.SerialNumber = big.NewInt(serial)
			template.RawSubject = utf8Name([][2]string{{"CN", dnsName}})
			template.NotBefore, template.NotAfter = date(2026, 5, 8, 21, 12, 21), date(2028, 8, 10, 21, 12, 21)
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.DNSNames = []string{dnsName}
			endEntityWithNoncriticalBasicConstraints(template)
		}, withSubjectKeyID)
	}
	good, err := leaf(0x08f0, "nc-good.example.test")
	if err != nil {
		return err
	}
	bad, err := leaf(0x08f1, "nc-bad.example.com")
	if err != nil {
		return err
	}
	for file, certificate := range map[string]issued{
		"nc-root.pem":         root,
		"nc-intermediate.pem": intermediate,
		"nc-good-leaf.pem":    good,
		"nc-bad-leaf.pem":     bad,
	} {
		if err := f.writeCerts(file, certificate); err != nil {
			return err
		}
	}
	return nil
}

// ca makes template a CA certificate for certificate and CRL signing; a
// negative pathLen omits the path length constraint.
func ca(template *x509.Certificate, pathLen int) {
	template.IsCA, template.BasicConstraintsValid = true, true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if pathLen >= 0 {
		template.MaxPathLen = pathLen
		template.MaxPathLenZero = pathLen == 0
	} else {
		template.MaxPathLen = -1
	}
}

// endEntityWithNoncriticalBasicConstraints adds basicConstraints cA=FALSE as
// a noncritical extension, as OpenSSL writes it; Go marks it critical.
func endEntityWithNoncriticalBasicConstraints(template *x509.Certificate) {
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 19},
		Value: []byte{0x30, 0x00},
	})
}

type option func(template *x509.Certificate, public crypto.PublicKey) error

// withSubjectKeyID sets the RFC 5280 method (1) key identifier, which Go
// adds only to CA certificates.
func withSubjectKeyID(template *x509.Certificate, public crypto.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return err
	}
	sum := sha1.Sum(info.PublicKey.Bytes) //nolint:gosec // RFC 5280 4.2.1.2 method (1)
	template.SubjectKeyId = sum[:]
	return nil
}

// issue creates an RSA-2048 certificate signed with SHA-256 by issuer, or
// self-signed when issuer is nil.
func issue(issuer *issued, configure func(template *x509.Certificate), options ...option) (issued, error) {
	return issueRSA(2048, issuer, configure, options...)
}

func issueRSA(bits int, issuer *issued, configure func(template *x509.Certificate), options ...option) (issued, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return issued{}, err
	}
	template := &x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA}
	configure(template)
	for _, apply := range options {
		if err := apply(template, key.Public()); err != nil {
			return issued{}, err
		}
	}
	parent, signer := template, crypto.Signer(key)
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

var attributeTypes = map[string]asn1.ObjectIdentifier{
	"C":  {2, 5, 4, 6},
	"ST": {2, 5, 4, 8},
	"L":  {2, 5, 4, 7},
	"O":  {2, 5, 4, 10},
	"OU": {2, 5, 4, 11},
	"CN": {2, 5, 4, 3},
}

// utf8Name encodes a distinguished name the way OpenSSL does by default:
// countryName as PrintableString, every other attribute as UTF8String.
func utf8Name(attributes [][2]string) []byte {
	rdns := make(pkix.RDNSequence, 0, len(attributes))
	for _, attribute := range attributes {
		value := asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(attribute[1])}
		if attribute[0] == "C" {
			value.Tag = asn1.TagPrintableString
		}
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: attributeTypes[attribute[0]], Value: value}})
	}
	der, err := asn1.Marshal(rdns)
	if err != nil {
		panic(err)
	}
	return der
}

func (f fixtures) writeCerts(file string, certificates ...issued) error {
	data := make([]byte, 0, 2048*len(certificates))
	for _, certificate := range certificates {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.cert.Raw})...)
	}
	return f.write(filepath.Join("certs", file), data)
}

func (f fixtures) writeCRL(file string, issuer issued, template *x509.RevocationList) error {
	der, err := x509.CreateRevocationList(rand.Reader, template, issuer.cert, issuer.key)
	if err != nil {
		return fmt.Errorf("CRL %s: %w", file, err)
	}
	return f.write(filepath.Join("crls", file), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

func (f fixtures) write(file string, data []byte) error {
	path := filepath.Join(f.dir, file)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
