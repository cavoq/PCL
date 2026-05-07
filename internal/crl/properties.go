package crl

import (
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

func IsIndirect(crl *x509.RevocationList) bool {
	if crl == nil {
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
