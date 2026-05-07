package policy

import (
	"slices"
	"strings"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/rule"
)

const (
	InputCert     = "cert"
	InputCRL      = "crl"
	InputOCSP     = "ocsp"
	InputTST      = "tst"
	InputSCT      = "sct"
	InputAttrCert = "attrCert"
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
	if len(p.AppliesTo) > 0 {
		return slices.Contains(p.AppliesTo, inputType)
	}

	if len(p.Rules) > 0 {
		inferredType := inferInputTypeFromRules(p.Rules)
		return inferredType == inputType || inferredType == ""
	}

	return true
}

func AppliesToCertificate(p Policy, cert *x509.Certificate) bool {
	if cert == nil || !AppliesToInput(p, InputCert) {
		return false
	}

	if len(p.CertType) == 0 {
		return true
	}

	for _, ct := range p.CertType {
		ct = oid.NormalizeOID(ct)

		switch ct {
		case "ca":
			if cert.BasicConstraintsValid && cert.IsCA {
				return true
			}
		case "root":
			if cert.BasicConstraintsValid && cert.IsCA && cert.Subject.String() == cert.Issuer.String() {
				return true
			}
		case "intermediate":
			if cert.BasicConstraintsValid && cert.IsCA && cert.Subject.String() != cert.Issuer.String() {
				return true
			}
		case "leaf":
			if !cert.BasicConstraintsValid || !cert.IsCA {
				return true
			}
		default:
			for _, eku := range cert.ExtKeyUsage {
				if oid.ExtKeyUsageToOID(eku) == ct {
					return true
				}
			}
		}
	}

	return false
}

func AppliesToCRL(p Policy, hasDeltaIndicator bool, isIndirectCRL bool) bool {
	if !appliesToCRLInput(p) {
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

func inferInputTypeFromRules(rules []rule.Rule) string {
	if len(rules) == 0 {
		return ""
	}

	target := rules[0].Target
	if strings.HasPrefix(target, "certificate.") || target == "certificate" {
		return InputCert
	}
	if strings.HasPrefix(target, "crl.") || target == "crl" {
		return InputCRL
	}
	if strings.HasPrefix(target, "ocsp.") || target == "ocsp" {
		return InputOCSP
	}

	if rules[0].When != nil && rules[0].When.Target != "" {
		whenTarget := rules[0].When.Target
		if strings.HasPrefix(whenTarget, "certificate.") || whenTarget == "certificate" {
			return InputCert
		}
		if strings.HasPrefix(whenTarget, "crl.") || whenTarget == "crl" {
			return InputCRL
		}
		if strings.HasPrefix(whenTarget, "ocsp.") || whenTarget == "ocsp" {
			return InputOCSP
		}
	}

	return ""
}

func appliesToCRLInput(p Policy) bool {
	if len(p.AppliesTo) > 0 {
		return slices.Contains(p.AppliesTo, InputCRL)
	}

	for _, r := range p.Rules {
		if strings.HasPrefix(r.Target, "crl.") || r.Target == "crl" {
			return true
		}
		if r.When != nil && (strings.HasPrefix(r.When.Target, "crl.") || r.When.Target == "crl") {
			return true
		}
	}

	return false
}
