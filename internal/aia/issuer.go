package aia

import "github.com/zmap/zcrypto/x509"

// SelectIssuer chooses the issuer certificate for child from a CA Issuers
// response. It returns matched=false when the result is only a fallback.
func SelectIssuer(child *x509.Certificate, candidates []*x509.Certificate) (*x509.Certificate, bool) {
	if child == nil || len(candidates) == 0 {
		return nil, false
	}

	for _, candidate := range candidates {
		if candidate.Subject.String() == child.Issuer.String() {
			return candidate, true
		}
	}

	if len(child.AuthorityKeyId) > 0 {
		for _, candidate := range candidates {
			if len(candidate.SubjectKeyId) > 0 && string(candidate.SubjectKeyId) == string(child.AuthorityKeyId) {
				return candidate, true
			}
		}
	}

	return candidates[0], false
}
