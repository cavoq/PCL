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
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
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
	response, err := ocsp.ParseResponse(OCSPResponseDER(t, issuer, responder, template), nil)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	return response
}

// OCSPResponseDER is OCSPResponse before parsing. A template Certificate is
// embedded as the responder certificate.
func OCSPResponseDER(t testing.TB, issuer, responder *Certificate, template ocsp.Response) []byte {
	t.Helper()
	der, err := ocsp.CreateResponse(issuer.Std, responder.Std, template, responder.Key)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	return der
}

// PSS describes RSASSA-PSS signature parameters: the message hash, the MGF1
// hash, and the salt length.
type PSS struct {
	Hash, MGFHash crypto.Hash
	SaltLength    int
}

// SignOCSPWithPSS re-signs the DER OCSP response der with key using
// RSASSA-PSS, replacing its signature algorithm and signature and keeping
// any embedded certificates. golang.org/x/crypto/ocsp cannot create such
// responses.
func SignOCSPWithPSS(t testing.TB, der []byte, key *rsa.PrivateKey, params PSS) []byte {
	t.Helper()
	input := cryptobyte.String(der)
	var response, status, outer, responseBytes, responseType, basicOctets, basic, tbs cryptobyte.String
	if !input.ReadASN1(&response, cryptobyte_asn1.SEQUENCE) ||
		!response.ReadASN1Element(&status, cryptobyte_asn1.ENUM) ||
		!response.ReadASN1(&outer, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
		!outer.ReadASN1(&responseBytes, cryptobyte_asn1.SEQUENCE) ||
		!responseBytes.ReadASN1Element(&responseType, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
		!responseBytes.ReadASN1(&basicOctets, cryptobyte_asn1.OCTET_STRING) ||
		!basicOctets.ReadASN1(&basic, cryptobyte_asn1.SEQUENCE) ||
		!basic.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!basic.SkipASN1(cryptobyte_asn1.SEQUENCE) || !basic.SkipASN1(cryptobyte_asn1.BIT_STRING) {
		t.Fatal("decode OCSP response for PSS signing")
	}
	certificates := basic // the optional [0] certs, possibly empty

	digest := params.Hash.New()
	digest.Write(tbs)
	signature, err := rsa.SignPSS(rand.Reader, key, params.Hash, digest.Sum(nil), &rsa.PSSOptions{SaltLength: params.SaltLength})
	if err != nil {
		t.Fatalf("sign OCSP response with PSS: %v", err)
	}
	algorithm, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		Parameters: asn1.RawValue{FullBytes: pssParameters(t, params)},
	})
	if err != nil {
		t.Fatal(err)
	}
	signatureBits, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)})
	if err != nil {
		t.Fatal(err)
	}

	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(status)
		b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(responseType)
				b.AddASN1(cryptobyte_asn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddBytes(tbs)
						b.AddBytes(algorithm)
						b.AddBytes(signatureBits)
						b.AddBytes(certificates)
					})
				})
			})
		})
	})
	resigned, err := builder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return resigned
}

// pssParameters encodes RSASSA-PSS-params with explicit hash, MGF1 and salt
// length fields.
func pssParameters(t testing.TB, params PSS) []byte {
	t.Helper()
	hashAlgorithm := func(hash crypto.Hash) pkix.AlgorithmIdentifier {
		oids := map[crypto.Hash]asn1.ObjectIdentifier{
			crypto.SHA256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
			crypto.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
			crypto.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
			crypto.SHA1:   {1, 3, 14, 3, 2, 26},
		}
		return pkix.AlgorithmIdentifier{Algorithm: oids[hash], Parameters: asn1.NullRawValue}
	}
	mgfHash, err := asn1.Marshal(hashAlgorithm(params.MGFHash))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(struct {
		Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
		MGF        pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
		SaltLength int                      `asn1:"explicit,tag:2"`
	}{
		Hash:       hashAlgorithm(params.Hash),
		MGF:        pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: mgfHash}},
		SaltLength: params.SaltLength,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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
