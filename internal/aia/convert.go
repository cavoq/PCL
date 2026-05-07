// Package aia provides AIA certificate extension parsing and issuer fetching.
package aia

import (
	certstd "crypto/x509"

	"github.com/cavoq/PCL/internal/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

func ToStdCert(cert *x509.Certificate) (*certstd.Certificate, error) {
	return zcrypto.ToStdCert(cert)
}
