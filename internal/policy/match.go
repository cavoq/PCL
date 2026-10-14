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
		ct = oid.NormalizeOID(ct)

		switch ct {
		case "ca":
			if isCA {
				return true
			}
		case "root":
			if isCA && selfSigned {
				return true
			}
		case "intermediate":
			if isCA && !selfSigned {
				return true
			}
		case "leaf":
			if !isCA {
				return true
			}
		default:
			for _, eku := range cert.ExtKeyUsage {
				if oid.ExtKeyUsageToOID(eku) == ct {
					return true
				}
			}
			for _, eku := range cert.UnknownExtKeyUsage {
				if eku.String() == ct {
					return true
				}
			}
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
