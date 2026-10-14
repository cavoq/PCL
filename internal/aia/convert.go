// Package aia provides AIA certificate extension parsing and issuer fetching.
package aia

import (
	certstd "crypto/x509"

	"github.com/cavoq/PCL/internal/x509node"
	"github.com/zmap/zcrypto/x509"
)

func ToStdCert(cert *x509.Certificate) (*certstd.Certificate, error) {
	return x509node.ToStdCert(cert)
}
