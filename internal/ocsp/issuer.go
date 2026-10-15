package ocsp

import (
	"bytes"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/x509asn1"
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
	if x509asn1.NamesMatchOrText(signer.RawIssuer, candidate.RawSubject, signer.Issuer.String(), candidate.Subject.String()) {
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

// SignerChain returns [responder, issuer, …] for signature-valid and AKI
// checks, without downloading anything. The issuer is the certificate in
// tlsChain or pool whose key verifies the responder. When it is on the TLS
// chain, the rest of that chain follows it; otherwise its issuers are found
// in tlsChain and pool by signature.
func SignerChain(signerInfo *cert.Info, tlsChain, pool []*cert.Info) []*cert.Info {
	if signerInfo == nil || signerInfo.Cert == nil {
		return tlsChain
	}
	candidates := append(append([]*cert.Info(nil), tlsChain...), pool...)
	issuer := SigningIssuerFromPool(signerInfo.Cert, cert.CertsFromInfos(candidates))
	if issuer == nil {
		return []*cert.Info{signerInfo}
	}
	if index, ok := indexInInfoChain(issuer, tlsChain); ok {
		return append([]*cert.Info{signerInfo}, tlsChain[index:]...)
	}
	index, _ := indexInInfoChain(issuer, candidates)
	return append([]*cert.Info{signerInfo}, cert.ExtendFromPool(candidates[index:index+1], candidates)...)
}

// DiscoverSignerIssuers downloads, through CA Issuers URLs, the issuer of a
// delegated OCSP responder that tlsChain does not contain, and that issuer's
// own issuers. It returns the downloaded certificates for SignerChain's pool.
func DiscoverSignerIssuers(
	signer *x509.Certificate,
	tlsChain []*cert.Info,
	timeout time.Duration,
	maxDepth int,
	w io.Writer,
) []*cert.Info {
	if signer == nil {
		return nil
	}
	issuer := SigningIssuerFromPool(signer, ResolveSignerIssuerPool(tlsChain, signer, timeout, maxDepth, w))
	if issuer == nil {
		return nil
	}
	if _, ok := indexInInfoChain(issuer, tlsChain); ok {
		return nil
	}
	issuerInfo := &cert.Info{Cert: issuer}
	return cert.ClimbChainWithPool([]*cert.Info{issuerInfo}, tlsChain, timeout, maxDepth, w)
}

func indexInInfoChain(target *x509.Certificate, chain []*cert.Info) (int, bool) {
	if target == nil {
		return 0, false
	}
	for i, info := range chain {
		if info != nil && cert.SameCertificate(target, info.Cert) {
			return i, true
		}
	}
	return 0, false
}
