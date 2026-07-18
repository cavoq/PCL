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
	if len(cert.RawSubject) > 0 && len(revocationList.RawIssuer) > 0 {
		if !bytes.Equal(cert.RawSubject, revocationList.RawIssuer) {
			return false
		}
	} else if cert.Subject.String() != revocationList.Issuer.String() {
		return false
	}

	keyIdentifier := crlzcrypto.AuthorityKeyIdentifier(revocationList)
	if len(keyIdentifier) > 0 && len(cert.SubjectKeyId) > 0 {
		return bytes.Equal(cert.SubjectKeyId, keyIdentifier)
	}
	return true
}

// CertSignsCRL reports whether cert is the named CRL issuer and
// cryptographically verifies its signature.
func CertSignsCRL(cert *x509.Certificate, revocationList *x509.RevocationList) bool {
	if !CertMatchesCRLIssuer(cert, revocationList) {
		return false
	}
	return revocationList.CheckSignatureFrom(cert) == nil
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
	if VerifyingCertFromPool(revocationList, pool) != nil {
		return pool
	}

	return cert.CollectViaCAIssuers(pool, cert.AIACollectConfig{
		Timeout:  timeout,
		MaxDepth: maxDepth,
		Warn:     w,
		StopWhen: func(c *x509.Certificate) bool {
			return CertSignsCRL(c, revocationList)
		},
	})
}
