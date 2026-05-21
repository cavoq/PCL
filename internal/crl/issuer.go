package crl

import (
	"bytes"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/zmap/zcrypto/x509"
)

const subscriberCRLMaxInterval = 10 * 24 * time.Hour

// CertMatchesCRLIssuer reports whether cert is the CRL signing certificate.
func CertMatchesCRLIssuer(cert *x509.Certificate, revocationList *x509.RevocationList) bool {
	if cert == nil || revocationList == nil {
		return false
	}
	if cert.Subject.String() == revocationList.Issuer.String() {
		return true
	}
	if len(revocationList.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 {
		return bytes.Equal(cert.SubjectKeyId, revocationList.AuthorityKeyId)
	}
	return false
}

// CertSignsCRL reports whether cert signed the CRL (DN/AKI match or signature verify).
func CertSignsCRL(cert *x509.Certificate, revocationList *x509.RevocationList) bool {
	if CertMatchesCRLIssuer(cert, revocationList) {
		return true
	}
	if cert == nil || revocationList == nil {
		return false
	}
	return revocationList.CheckSignatureFrom(cert) == nil
}

// SigningCertFromPool returns the first certificate in pool that signed the CRL.
func SigningCertFromPool(revocationList *x509.RevocationList, pool []*x509.Certificate) *x509.Certificate {
	for _, c := range pool {
		if CertSignsCRL(c, revocationList) {
			return c
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
	if SigningCertFromPool(revocationList, pool) != nil {
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
