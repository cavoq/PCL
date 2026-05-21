package ocsp

import (
	"bytes"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/zmap/zcrypto/x509"
)

// SigningIssuerFromPool returns the certificate that signed signer. DN/AKI hints
// alone are not used (same policy as cert.findSigningParentInPool).
func SigningIssuerFromPool(signer *x509.Certificate, pool []*x509.Certificate) *x509.Certificate {
	if signer == nil {
		return nil
	}
	for _, c := range pool {
		if c != nil && signer.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

func certMatchesSignerIssuer(signer, candidate *x509.Certificate) bool {
	if signer == nil || candidate == nil {
		return false
	}
	if signer.Issuer.String() == candidate.Subject.String() {
		return true
	}
	if len(signer.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 {
		return bytes.Equal(signer.AuthorityKeyId, candidate.SubjectKeyId)
	}
	return false
}

// ResolveSignerIssuerPool returns TLS chain certificates plus any issuer needed to
// verify the OCSP responder certificate (AKI/signature match or CA Issuers fetch).
func ResolveSignerIssuerPool(
	tlsChain []*cert.Info,
	signer *x509.Certificate,
	timeout time.Duration,
	maxDepth int,
	w io.Writer,
) []*x509.Certificate {
	pool := cert.CertsFromInfos(tlsChain)
	if signer == nil {
		return pool
	}
	if SigningIssuerFromPool(signer, pool) != nil {
		return pool
	}
	return cert.CollectViaCAIssuers(append(pool, signer), cert.AIACollectConfig{
		Timeout:  timeout,
		MaxDepth: maxDepth,
		Warn:     w,
		StopWhen: func(c *x509.Certificate) bool {
			return signer.CheckSignatureFrom(c) == nil
		},
	})
}

// BuildSignerEvalChain returns [OCSP responder, issuer, …] for signature-valid and
// AKI checks. The responder is always index 0; the tail is taken from tlsChain when
// the issuer is already on the TLS path, otherwise from pool lookup and AIA climb.
func BuildSignerEvalChain(
	signer *x509.Certificate,
	signerInfo *cert.Info,
	tlsChain []*cert.Info,
	timeout time.Duration,
	maxDepth int,
	w io.Writer,
) []*cert.Info {
	if signer == nil || signerInfo == nil {
		return tlsChain
	}

	pool := ResolveSignerIssuerPool(tlsChain, signer, timeout, maxDepth, w)
	issuerCert := SigningIssuerFromPool(signer, pool)
	if issuerCert == nil {
		out := []*cert.Info{signerInfo}
		cert.RebuildChainMetadata(out)
		return out
	}

	if idx, ok := indexInInfoChain(issuerCert, tlsChain); ok {
		out := append([]*cert.Info{signerInfo}, tlsChain[idx:]...)
		cert.RebuildChainMetadata(out)
		return out
	}

	issuerInfo := infoFromPoolCert(issuerCert, tlsChain)
	tail := []*cert.Info{issuerInfo}
	poolInfos := append([]*cert.Info(nil), tlsChain...)
	poolInfos = append(poolInfos, tail...)
	tail = cert.ClimbChainWithPool(tail, poolInfos, timeout, maxDepth, w)

	out := append([]*cert.Info{signerInfo}, tail...)
	cert.RebuildChainMetadata(out)
	return out
}

func indexInInfoChain(target *x509.Certificate, chain []*cert.Info) (int, bool) {
	if target == nil || target.SerialNumber == nil {
		return 0, false
	}
	serial := target.SerialNumber.String()
	for i, info := range chain {
		if info != nil && info.Cert != nil && info.Cert.SerialNumber != nil &&
			info.Cert.SerialNumber.String() == serial {
			return i, true
		}
	}
	return 0, false
}

func infoFromPoolCert(c *x509.Certificate, tlsChain []*cert.Info) *cert.Info {
	if c == nil {
		return nil
	}
	if idx, ok := indexInInfoChain(c, tlsChain); ok {
		return tlsChain[idx]
	}
	return &cert.Info{Cert: c}
}
