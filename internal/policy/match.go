package policy

import (
	"github.com/zmap/zcrypto/x509"

	certpkg "github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/oid"
)

func ByInput(policies []Policy, inputType string) []Policy {
	var filtered []Policy
	for _, p := range policies {
		if AppliesToInput(p, inputType) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func ByCertificate(policies []Policy, cert *x509.Certificate) []Policy {
	var filtered []Policy
	for _, p := range policies {
		if AppliesToCertificate(p, cert) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func ByCRL(policies []Policy, revocationList *x509.RevocationList) []Policy {
	var filtered []Policy
	hasDeltaIndicator := crl.HasDeltaIndicator(revocationList)
	isIndirect := crl.IsIndirect(revocationList)
	for _, p := range policies {
		if AppliesToCRL(p, hasDeltaIndicator, isIndirect) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func AppliesToInput(p Policy, inputType string) bool {
	return scopeForPolicy(p).appliesTo(inputKind(inputType))
}

func AppliesToCertificate(p Policy, cert *x509.Certificate) bool {
	if cert == nil || !AppliesToInput(p, InputCert) {
		return false
	}

	if len(p.CertType) == 0 {
		return true
	}

	isCA := certpkg.IsCA(cert)
	selfSigned := certpkg.IsSelfSigned(cert)
	for _, ct := range p.CertType {
		if certificateMatchesType(cert, oid.NormalizeOID(ct), isCA, selfSigned) {
			return true
		}
	}
	return false
}

// certificateMatchesType reports whether cert has the policy-level role
// certType: ca, root, intermediate, leaf, or an extended key usage OID.
func certificateMatchesType(cert *x509.Certificate, certType string, isCA, selfSigned bool) bool {
	switch certType {
	case "ca":
		return isCA
	case "root":
		return isCA && selfSigned
	case "intermediate":
		return isCA && !selfSigned
	case "leaf":
		return !isCA
	default:
		return hasExtendedKeyUsage(cert, certType)
	}
}

func hasExtendedKeyUsage(cert *x509.Certificate, identifier string) bool {
	for _, eku := range cert.ExtKeyUsage {
		if oid.ExtKeyUsageToOID(eku) == identifier {
			return true
		}
	}
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.String() == identifier {
			return true
		}
	}
	return false
}

func AppliesToCRL(p Policy, hasDeltaIndicator bool, isIndirectCRL bool) bool {
	if !AppliesToInput(p, InputCRL) {
		return false
	}

	if len(p.CRLType) == 0 {
		return true
	}

	for _, ct := range p.CRLType {
		ct = oid.NormalizeOID(ct)

		switch ct {
		case oid.DeltaCRLIndicator:
			if hasDeltaIndicator {
				return true
			}
		case "indirectCRL":
			if isIndirectCRL {
				return true
			}
		case "completeCRL":
			if !hasDeltaIndicator {
				return true
			}
		}
	}

	return false
}
