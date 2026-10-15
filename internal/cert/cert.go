// Package cert provides certificate loading, parsing and chain building.
package cert

import (
	"errors"

	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/x509asn1"
)

var extensions = []string{".pem", ".der", ".crt", ".cer"}

type Info struct {
	Cert     *x509.Certificate
	FilePath string
	Hash     string
	Position int
	Type     string
	Source   source.Info
}

// ParseCertificates parses a DER certificate or every CERTIFICATE block of
// PEM data. Other PEM blocks, such as keys, are ignored.
func ParseCertificates(data []byte) ([]*x509.Certificate, source.Format, error) {
	return source.DecodePEMOrDER(data, "CERTIFICATE", x509.ParseCertificate)
}

// IsSelfSigned reports whether the certificate is self-issued and verifies
// with its own public key, the form of a trust anchor certificate. A
// self-issued certificate signed with another key, such as a key rollover
// certificate, is not self-signed. Certificates constructed without encoded
// signature data fall back to the self-issued name comparison.
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil || !IsSelfIssued(cert) {
		return false
	}
	if len(cert.RawTBSCertificate) == 0 || len(cert.Signature) == 0 {
		return true
	}
	return SignedBy(cert, cert)
}

// CheckSignatureFrom verifies that parent issued child: parent must be
// allowed to sign certificates (a CA whose key usage, when present, includes
// keyCertSign; RFC 5280 4.2.1.9 and 6.1.4 (k)(n)), parent's subject must
// match child's issuer by the RFC 5280 Section 7.1 rules, and parent's key
// must verify child's signature. It applies the same authority rules as
// zcrypto's CheckSignatureFrom, which compares names byte for byte.
func CheckSignatureFrom(child, parent *x509.Certificate) error {
	if child == nil || parent == nil {
		return errors.New("missing certificate")
	}
	if parent.Version == 3 && !parent.BasicConstraintsValid || parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	if !x509asn1.NamesMatchOrText(child.RawIssuer, parent.RawSubject, child.Issuer.String(), parent.Subject.String()) {
		return errors.New("issuer name does not match the parent subject")
	}
	return parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
}

// SignedBy reports whether issuer's public key verifies child's signature.
// It checks the signature only; whether issuer may sign certificates is a
// separate path validation step.
func SignedBy(child, issuer *x509.Certificate) bool {
	if child == nil || issuer == nil {
		return false
	}
	return issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

// IsCA reports whether the certificate's strictly decoded basicConstraints
// extension asserts cA. Certificate roles and policy certType filters share
// this decision so a malformed extension classifies the same everywhere.
func IsCA(cert *x509.Certificate) bool {
	basicConstraints, valid := basicConstraintsProfileFacts(cert)
	return valid && basicConstraints.CA
}

// Evaluation-context types. GetCertType assigns the certificate roles, and
// rule-level certType filters match against all of them.
const (
	TypeRoot         = "root"
	TypeIntermediate = "intermediate"
	TypeLeaf         = "leaf"
	TypeOCSPSigning  = "ocspSigning"
	// TypeCRL and TypeOCSP mark contexts for CRL and OCSP response inputs.
	TypeCRL  = "crl"
	TypeOCSP = "ocsp"
)

// GetCertType classifies a certificate's role from its own contents.
func GetCertType(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	if IsCA(cert) {
		if IsSelfSigned(cert) {
			return TypeRoot
		}
		return TypeIntermediate
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOcspSigning {
			return TypeOCSPSigning
		}
	}

	return TypeLeaf
}
