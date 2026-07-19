package cert

import (
	"bytes"

	"github.com/zmap/zcrypto/x509"
)

// PathLenConstraintValid checks the current certificate's pathLenConstraint
// against the supplied leaf-to-root chain. It counts only non-self-issued
// intermediate certificates below the current certificate; the target at
// position zero is never an intermediate, even when it is itself a CA.
//
// This is a bounded profile check, not RFC 5280 Section 6 path validation. In
// particular, it relies on the caller's already ordered chain and uses exact
// encoded-name equality (with a parsed-name fallback) for self-issued status.
func PathLenConstraintValid(current *Info, chain []*Info) bool {
	if current == nil || current.Cert == nil || len(chain) == 0 {
		return false
	}

	position, ok := certificatePosition(current, chain)
	if !ok {
		return false
	}
	constraint, valid := basicConstraintsProfileFacts(current.Cert)
	if !valid {
		return false
	}
	if !constraint.PathLenConstraintPresent {
		return true
	}
	if !BasicConstraintsDependenciesValid(current.Cert) {
		return false
	}

	nonSelfIssuedIntermediates := 0
	for index, candidate := range chain {
		if index == 0 {
			continue
		}
		if index >= position {
			break
		}
		if candidate == nil || candidate.Cert == nil {
			return false
		}
		if !IsSelfIssued(candidate.Cert) {
			nonSelfIssuedIntermediates++
		}
	}
	if !constraint.PathLenConstraintFitsInt {
		// Any value beyond native int exceeds the largest representable chain
		// count in this process.
		return true
	}
	return nonSelfIssuedIntermediates <= constraint.PathLenConstraint
}

// IsSelfIssued reports whether a certificate's subject and issuer names are
// the same. Exact DER equality is intentionally used when available; complete
// RFC 5280 Section 7 name comparison remains P4 work.
func IsSelfIssued(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	if len(certificate.RawSubject) > 0 && len(certificate.RawIssuer) > 0 {
		return bytes.Equal(certificate.RawSubject, certificate.RawIssuer)
	}
	return certificate.Subject.String() == certificate.Issuer.String()
}

func certificatePosition(current *Info, chain []*Info) (int, bool) {
	position := current.Position
	if position >= 0 && position < len(chain) && sameCertificateInfo(current, chain[position]) {
		return position, true
	}
	for index, candidate := range chain {
		if sameCertificateInfo(current, candidate) {
			return index, true
		}
	}
	return 0, false
}

func sameCertificateInfo(left, right *Info) bool {
	if left == nil || right == nil || left.Cert == nil || right.Cert == nil {
		return false
	}
	if left == right || left.Cert == right.Cert {
		return true
	}
	return len(left.Cert.Raw) > 0 && bytes.Equal(left.Cert.Raw, right.Cert.Raw)
}
