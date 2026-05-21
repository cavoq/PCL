package crl

import (
	"github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
)

// BuildTree builds a CRL node tree without isCACRL (for embedding under certificates).
func BuildTree(revocationList *x509.RevocationList) *node.Node {
	return zcrypto.BuildTree(revocationList)
}

// BuildTreeWithChain builds a CRL node tree and sets isCACRL from issuerCerts.
// isCACRL is true when the CRL signing certificate is a CA, or when the CRL
// validity window exceeds the BR 7.2 subscriber CRL maximum (other CRL profile).
func BuildTreeWithChain(revocationList *x509.RevocationList, issuerCerts []*x509.Certificate) *node.Node {
	if revocationList == nil {
		return nil
	}
	n := zcrypto.BuildTree(revocationList)
	if n == nil {
		return nil
	}

	n.Children["isCACRL"] = node.New("isCACRL", isCACRL(revocationList, issuerCerts))
	return n
}

func isCACRL(revocationList *x509.RevocationList, issuerCerts []*x509.Certificate) bool {
	if signer := SigningCertFromPool(revocationList, issuerCerts); signer != nil && signer.IsCA {
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
