package crl

import (
	"bytes"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

const subscriberCRLMaxInterval = 10 * 24 * time.Hour

// CertMatchesCRLIssuer reports whether cert is the CRL signing certificate.
func CertMatchesCRLIssuer(cert *x509.Certificate, revocationList *x509.RevocationList) bool {
	if cert == nil || revocationList == nil {
		return false
	}
	if !certSubjectMatchesCRLIssuer(cert, revocationList) {
		return false
	}

	keyIdentifier := crlzcrypto.AuthorityKeyIdentifier(revocationList)
	if len(keyIdentifier) > 0 {
		return len(cert.SubjectKeyId) > 0 && bytes.Equal(cert.SubjectKeyId, keyIdentifier)
	}
	return true
}

func certSubjectMatchesCRLIssuer(
	cert *x509.Certificate,
	revocationList *x509.RevocationList,
) bool {
	if len(cert.RawSubject) > 0 && len(revocationList.RawIssuer) > 0 {
		return bytes.Equal(cert.RawSubject, revocationList.RawIssuer)
	}
	return cert.Subject.String() == revocationList.Issuer.String()
}

// CertSignsCRL reports whether cert is the named CRL issuer and
// cryptographically verifies its signature.
func CertSignsCRL(cert *x509.Certificate, revocationList *x509.RevocationList) bool {
	if !CertMatchesCRLIssuer(cert, revocationList) {
		return false
	}
	return certVerifiesCRLSignature(cert, revocationList)
}

func certVerifiesCRLSignature(
	cert *x509.Certificate,
	revocationList *x509.RevocationList,
) bool {
	if cert == nil || revocationList == nil {
		return false
	}
	// RevocationList.CheckSignatureFrom also applies zcrypto's CA and KeyUsage
	// policy. RFC 5280 Section 6.3 treats those as separate steps: a dedicated
	// CRL signer need not be a CA, and cRLSign is required only when Key Usage
	// is present. Keep this helper cryptographic; the revocation assessment
	// owns cRLSign and its P4 signer-path authorization hook.
	return cert.CheckSignature(
		revocationList.SignatureAlgorithm,
		revocationList.RawTBSRevocationList,
		revocationList.Signature,
	) == nil
}

// SigningCertFromPool returns a certificate that is both the named CRL issuer
// and a cryptographic verifier. It is retained as the public signer-selection
// entry point; callers needing identity hints use matchingCertFromPool.
func SigningCertFromPool(revocationList *x509.RevocationList, pool []*x509.Certificate) *x509.Certificate {
	return VerifyingCertFromPool(revocationList, pool)
}

func matchingCertFromPool(revocationList *x509.RevocationList, pool []*x509.Certificate) *x509.Certificate {
	if revocationList == nil {
		return nil
	}
	for _, candidate := range pool {
		if CertMatchesCRLIssuer(candidate, revocationList) {
			return candidate
		}
	}
	return nil
}

// VerifyingCertFromPool returns only a certificate whose subject identifies
// the CRL issuer, whose SKI is consistent with the CRL AKI when both exist,
// and whose public key cryptographically verifies the CRL signature.
func VerifyingCertFromPool(revocationList *x509.RevocationList, pool []*x509.Certificate) *x509.Certificate {
	if revocationList == nil {
		return nil
	}
	for _, candidate := range pool {
		if candidate == nil {
			continue
		}
		if CertSignsCRL(candidate, revocationList) {
			return candidate
		}
	}
	return nil
}

func usableCRLSignerFromPool(
	revocationList *x509.RevocationList,
	pool []*x509.Certificate,
) *x509.Certificate {
	for _, candidate := range pool {
		if usableCRLSigner(candidate, revocationList) {
			return candidate
		}
	}
	return nil
}

func usableCRLSigner(cert *x509.Certificate, revocationList *x509.RevocationList) bool {
	return CertSignsCRL(cert, revocationList) && crlSignUsagePermits(cert)
}

// ResolveIssuerCerts returns chain certificates plus any CRL signing certificates
// discovered via Authority Key Identifier match, signature verify, or CA Issuers fetch.
func ResolveIssuerCerts(
	chain []*cert.Info,
	revocationList *x509.RevocationList,
	timeout time.Duration,
	maxDepth int,
	w io.Writer,
) []*x509.Certificate {
	pool := cert.CertsFromInfos(chain)
	if revocationList == nil {
		return pool
	}
	if usableCRLSignerFromPool(revocationList, pool) != nil {
		return pool
	}

	return cert.CollectViaCAIssuers(pool, cert.AIACollectConfig{
		Timeout:  timeout,
		MaxDepth: maxDepth,
		Warn:     w,
		StopWhen: func(c *x509.Certificate) bool {
			return usableCRLSigner(c, revocationList)
		},
	})
}
