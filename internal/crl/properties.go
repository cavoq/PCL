package crl

import (
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/oid"
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

func HasIssuingDistributionPoint(crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}
	for _, ext := range crl.Extensions {
		if ext.Id.String() == oid.IssuingDistributionPoint {
			return true
		}
	}
	return false
}

func HasCriticalExtension(crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}
	for _, ext := range crl.Extensions {
		if ext.Critical {
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
	if !HasIssuingDistributionPoint(crl) {
		return false
	}
	for _, ext := range crl.Extensions {
		if ext.Id.String() == oid.IssuingDistributionPoint {
			return hasIndirectCRLInExtension(ext.Value)
		}
	}
	return false
}

func hasIndirectCRLInExtension(extValue []byte) bool {
	for i := 0; i < len(extValue)-1; i++ {
		if extValue[i] == 0x84 && extValue[i+1] == 0x01 && i+2 < len(extValue) {
			return extValue[i+2] == 0xff
		}
	}
	return false
}
