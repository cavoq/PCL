package aia

import (
	"bytes"

	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/zmap/zcrypto/x509"
)

// SelectIssuer chooses the issuer certificate for child from a CA Issuers
// response. It returns matched=false when no candidate is suitable.
func SelectIssuer(child *x509.Certificate, candidates []*x509.Certificate) (*x509.Certificate, bool) {
	if child == nil || len(candidates) == 0 {
		return nil, false
	}

	if len(child.Raw) > 0 {
		for _, candidate := range candidates {
			if candidate == nil {
				continue
			}
			if child.CheckSignatureFrom(candidate) == nil {
				return candidate, true
			}
		}
	}

	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if x509asn1.NamesMatchOrText(child.RawIssuer, candidate.RawSubject, child.Issuer.String(), candidate.Subject.String()) {
			return candidate, true
		}
	}

	if len(child.AuthorityKeyId) > 0 {
		for _, candidate := range candidates {
			if candidate == nil {
				continue
			}
			if len(candidate.SubjectKeyId) > 0 &&
				bytes.Equal(candidate.SubjectKeyId, child.AuthorityKeyId) {
				return candidate, true
			}
		}
	}

	return nil, false
}
