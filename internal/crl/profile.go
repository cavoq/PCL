package crl

import (
	"github.com/zmap/zcrypto/x509"
)

// IsCACRL reports whether the CRL follows the CA / other-CRL profile used by BR policies.
func IsCACRL(revocationList *x509.RevocationList, issuerCerts []*x509.Certificate) bool {
	return isCACRL(revocationList, issuerCerts)
}

func isCACRL(revocationList *x509.RevocationList, issuerCerts []*x509.Certificate) bool {
	if signer := SigningCertFromPool(revocationList, issuerCerts); signer != nil && signer.IsCA {
		return true
	}
	// Profile classification may use an identity hint when a synthetic or
	// otherwise unverifiable CRL is inspected. Security decisions never use
	// this fallback; CRLSignedBy and revocation status require verification.
	if signer := matchingCertFromPool(revocationList, issuerCerts); signer != nil && signer.IsCA {
		return true
	}
	return inferCACRLFromValidity(revocationList)
}

// inferCACRLFromValidity applies BR 7.2: subscriber-scope CRLs must have
// nextUpdate within 10 days of thisUpdate; a longer window implies the other CRL profile.
func inferCACRLFromValidity(revocationList *x509.RevocationList) bool {
	if revocationList == nil || revocationList.NextUpdate.IsZero() {
		return false
	}
	return revocationList.NextUpdate.Sub(revocationList.ThisUpdate) > subscriberCRLMaxInterval
}
