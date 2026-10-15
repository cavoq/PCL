package crl

import (
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
)

func HasDeltaIndicator(crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}
	for _, ext := range crl.Extensions {
		if ext.Id.String() == oid.DeltaCRLIndicator {
			return true
		}
	}
	return false
}

// IsCurrentAt applies the RFC 5280 CRL time window. Conforming CRLs include
// nextUpdate, and both boundary instants are accepted.
func IsCurrentAt(crl *x509.RevocationList, now time.Time) bool {
	if crl == nil || now.IsZero() || crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() {
		return false
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		return false
	}
	return !now.Before(crl.ThisUpdate) && !now.After(crl.NextUpdate)
}

// IsNotExpiredAt checks only the nextUpdate deadline. It is kept separate
// from IsCurrentAt for the compatibility crlNotExpired operator.
func IsNotExpiredAt(crl *x509.RevocationList, now time.Time) bool {
	if crl == nil || now.IsZero() || crl.NextUpdate.IsZero() {
		return false
	}
	return !now.After(crl.NextUpdate)
}

func IsIndirect(crl *x509.RevocationList) bool {
	facts, err := x509ext.DecodeRevocationListStrict(crl)
	return err == nil && facts.IssuingDistributionPoint != nil &&
		facts.IssuingDistributionPoint.IndirectCRL
}
