// Package testpki issues certificates, CRLs and OCSP responses for tests and
// serves test data over HTTP.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/ocsp"
)

// NotBefore and NotAfter bound the validity of issued certificates unless
// an option changes it.
var (
	NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	NotAfter  = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Certificate is an issued certificate with its private key, as DER and in
// both parsed representations.
type Certificate struct {
	DER  []byte
	Std  *x509.Certificate
	Cert *zx509.Certificate
	Key  crypto.Signer
}

// Option adjusts the template of a certificate before it is issued.
type Option func(*x509.Certificate)

// CA makes the certificate a CA that may sign certificates and CRLs.
func CA() Option {
	return func(template *x509.Certificate) {
		template.BasicConstraintsValid = true
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
}

// OCSPSigning makes the certificate a delegated OCSP responder.
func OCSPSigning() Option {
	return func(template *x509.Certificate) {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
}

// Serial sets the serial number.
func Serial(serial int64) Option {
	return func(template *x509.Certificate) { template.SerialNumber = big.NewInt(serial) }
}

// SubjectKeyID sets the subject key identifier.
func SubjectKeyID(id []byte) Option {
	return func(template *x509.Certificate) { template.SubjectKeyId = id }
}

// IssuingCertificateURLs sets the CA Issuers locations of the AIA extension.
func IssuingCertificateURLs(urls ...string) Option {
	return func(template *x509.Certificate) { template.IssuingCertificateURL = urls }
}

// Validity sets the validity period.
func Validity(notBefore, notAfter time.Time) Option {
	return func(template *x509.Certificate) { template.NotBefore, template.NotAfter = notBefore, notAfter }
}

// Mutate applies any other template change.
func Mutate(change func(*x509.Certificate)) Option {
	return Option(change)
}

// Issue creates a certificate for subject signed by issuer, or self-signed
// when issuer is nil, with a new RSA key.
func Issue(t testing.TB, subject string, issuer *Certificate, options ...Option) *Certificate {
	t.Helper()
	return IssueWithKey(t, subject, RSAKey(t), issuer, options...)
}

// IssueWithKey is Issue with the subject's key supplied.
func IssueWithKey(t testing.TB, subject string, key crypto.Signer, issuer *Certificate, options ...Option) *Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    NotBefore,
		NotAfter:     NotAfter,
	}
	for _, option := range options {
		option(template)
	}
	// Signing with the parsed issuer gives the certificate an authority key
	// identifier whenever the issuer has a subject key identifier, which Go
	// generates for CA certificates.
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.Std, issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatalf("create certificate %q: %v", subject, err)
	}
	return &Certificate{DER: der, Std: parse(t, der), Cert: ParseZCrypto(t, der), Key: key}
}

// RevocationList signs template as a CRL issued by c. A missing number and
// update times are filled in.
func (c *Certificate) RevocationList(t testing.TB, template *x509.RevocationList) []byte {
	t.Helper()
	if template.Number == nil {
		template.Number = big.NewInt(1)
	}
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate = c.Std.NotBefore
	}
	if template.NextUpdate.IsZero() {
		template.NextUpdate = c.Std.NotAfter
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, c.Std, c.Key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}

// OCSPResponse signs template with the key of responder as a response about
// a certificate issued by issuer, and parses it.
func OCSPResponse(t testing.TB, issuer, responder *Certificate, template ocsp.Response) *ocsp.Response {
	t.Helper()
	der, err := ocsp.CreateResponse(issuer.Std, responder.Std, template, responder.Key)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	response, err := ocsp.ParseResponse(der, nil)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	return response
}

// RSAKey generates an RSA-2048 key.
func RSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// ECDSAKey generates a P-256 key.
func ECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// Serve answers every request with body until the test ends and returns the
// server URL.
func Serve(t testing.TB, body []byte) string {
	t.Helper()
	url, _ := ServeCounted(t, body)
	return url
}

// ServeCounted is Serve that also counts the requests.
func ServeCounted(t testing.TB, body []byte) (string, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server.URL, hits
}

// ParseZCrypto parses a DER certificate with zcrypto.
func ParseZCrypto(t testing.TB, der []byte) *zx509.Certificate {
	t.Helper()
	certificate, err := zx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

// PEM encodes der as a PEM block of blockType.
func PEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func parse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

// ZCryptoWithExtension self-signs a certificate carrying extension verbatim
// and parses it with zcrypto only, which accepts encodings that
// crypto/x509 rejects, such as BER-encoded booleans.
func ZCryptoWithExtension(t testing.TB, extension pkix.Extension) *zx509.Certificate {
	t.Helper()
	key := RSAKey(t)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Extension Probe"},
		NotBefore:       NotBefore,
		NotAfter:        NotAfter,
		ExtraExtensions: []pkix.Extension{extension},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return ParseZCrypto(t, der)
}
