package crl

import (
	"bytes"
	"time"

	"github.com/zmap/zcrypto/x509"
)

type RevocationStatus uint8

const (
	RevocationUnknown RevocationStatus = iota
	RevocationGood
	RevocationRevoked
)

type RevocationContext struct {
	Now     time.Time
	Issuers []*x509.Certificate
}

// StatusForCertificate evaluates the serial number against applicable CRLs.
// A clean result is returned only when at least one CRL matches the
// certificate issuer; absence of revocation data remains unknown.
func StatusForCertificate(certificate *x509.Certificate, lists []*x509.RevocationList, ctx RevocationContext) RevocationStatus {
	if certificate == nil || certificate.SerialNumber == nil {
		return RevocationUnknown
	}

	foundAccepted := false
	for _, list := range lists {
		if !acceptedForCertificate(list, certificate, ctx) {
			continue
		}
		foundAccepted = true
		for _, revoked := range list.RevokedCertificates {
			if revoked.SerialNumber != nil && revoked.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return RevocationRevoked
			}
		}
	}

	if foundAccepted {
		return RevocationGood
	}
	return RevocationUnknown
}

func acceptedForCertificate(list *x509.RevocationList, certificate *x509.Certificate, ctx RevocationContext) bool {
	if list == nil || certificate == nil {
		return false
	}
	if !crlIssuerMatchesCertificateIssuer(list, certificate) || !IsCurrentAt(list, ctx.Now) {
		return false
	}
	// This resolver implements only complete, direct, unscoped CRLs and does
	// not process any CRL-level critical extension. Delta, IDP-scoped, or other
	// critically extended CRLs therefore cannot prove a certificate good.
	if HasCriticalExtension(list) || HasDeltaIndicator(list) || HasIssuingDistributionPoint(list) {
		return false
	}
	return VerifyingCertFromPool(list, ctx.Issuers) != nil
}

func crlIssuerMatchesCertificateIssuer(list *x509.RevocationList, certificate *x509.Certificate) bool {
	if len(list.RawIssuer) > 0 && len(certificate.RawIssuer) > 0 {
		return bytes.Equal(list.RawIssuer, certificate.RawIssuer)
	}
	return list.Issuer.String() == certificate.Issuer.String()
}
