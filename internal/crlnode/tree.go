package crlnode

import (
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
)

// BuildTreeWithChain builds a CRL node tree and sets isCACRL from issuerCerts.
// isCACRL is true when the CRL signing certificate is a CA, or when the CRL
// validity window exceeds the BR 7.2 subscriber CRL maximum (other CRL profile).
func BuildTreeWithChain(revocationList *x509.RevocationList, issuerCerts []*x509.Certificate) *node.Node {
	if revocationList == nil {
		return nil
	}
	n := BuildTree(revocationList)
	if n == nil {
		return nil
	}

	n.Children["isCACRL"] = node.New("isCACRL", crl.IsCACRL(revocationList, issuerCerts))
	return n
}
