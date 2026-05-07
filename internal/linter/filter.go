package linter

import (
	"slices"
	"strings"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

// AppliesTo types - fixed enumeration for PKI input types
const (
	AppliesToCert     = "cert"
	AppliesToCRL      = "crl"
	AppliesToOCSP     = "ocsp"
	AppliesToTST      = "tst"
	AppliesToSCT      = "sct"
	AppliesToAttrCert = "attrCert"
)

// policyAppliesToInput checks if a policy applies to the given input type
func policyAppliesToInput(p policy.Policy, inputType string) bool {
	// If AppliesTo is explicitly set, use it
	if len(p.AppliesTo) > 0 {
		return slices.Contains(p.AppliesTo, inputType)
	}

	// Infer from rule targets if AppliesTo is not set
	// If all targets start with "certificate.", it's a cert policy
	// If all targets start with "crl.", it's a CRL policy
	// If all targets start with "ocsp.", it's an OCSP policy
	if len(p.Rules) > 0 {
		inferredType := inferInputTypeFromRules(p.Rules)
		return inferredType == inputType || inferredType == ""
	}

	// Default: apply to all (backward compatible for empty policies)
	return true
}

// inferInputTypeFromRules determines the input type from rule targets
func inferInputTypeFromRules(rules []rule.Rule) string {
	if len(rules) == 0 {
		return ""
	}

	// Check first rule target
	target := rules[0].Target
	if strings.HasPrefix(target, "certificate.") || target == "certificate" {
		return AppliesToCert
	}
	if strings.HasPrefix(target, "crl.") || target == "crl" {
		return AppliesToCRL
	}
	if strings.HasPrefix(target, "ocsp.") || target == "ocsp" {
		return AppliesToOCSP
	}

	// Check "when" condition target if main target doesn't indicate type
	if rules[0].When != nil && rules[0].When.Target != "" {
		whenTarget := rules[0].When.Target
		if strings.HasPrefix(whenTarget, "certificate.") || whenTarget == "certificate" {
			return AppliesToCert
		}
		if strings.HasPrefix(whenTarget, "crl.") || whenTarget == "crl" {
			return AppliesToCRL
		}
		if strings.HasPrefix(whenTarget, "ocsp.") || whenTarget == "ocsp" {
			return AppliesToOCSP
		}
	}

	// Unknown target format, apply to all
	return ""
}

// policyAppliesToCert checks if a policy applies to a specific certificate
func policyAppliesToCert(p policy.Policy, cert *x509.Certificate) bool {
	// Check input type first
	if !policyAppliesToInput(p, AppliesToCert) {
		return false
	}

	// If no certType filter, applies to all certs
	if len(p.CertType) == 0 {
		return true
	}

	// Check each certType constraint
	for _, ct := range p.CertType {
		ct = oid.NormalizeOID(ct)

		// Built-in types
		if ct == "ca" {
			if cert.BasicConstraintsValid && cert.IsCA {
				return true
			}
			continue
		}
		if ct == "root" {
			// Root CA: self-signed (Subject == Issuer) and isCA
			if cert.BasicConstraintsValid && cert.IsCA && cert.Subject.String() == cert.Issuer.String() {
				return true
			}
			continue
		}
		if ct == "intermediate" {
			// Intermediate CA: has different issuer (not self-signed) and isCA
			if cert.BasicConstraintsValid && cert.IsCA && cert.Subject.String() != cert.Issuer.String() {
				return true
			}
			continue
		}
		if ct == "leaf" {
			if !cert.BasicConstraintsValid || !cert.IsCA {
				return true
			}
			continue
		}

		// EKU OID check
		for _, eku := range cert.ExtKeyUsage {
			ekuOID := oid.ExtKeyUsageToOID(eku)
			if ekuOID == ct {
				return true
			}
		}
	}

	return false
}

// policyAppliesToCRL checks if a policy applies to a specific CRL
func policyAppliesToCRL(p policy.Policy, hasDeltaIndicator bool, isIndirectCRL bool) bool {
	// Check input type first
	if !policyAppliesToCRLInput(p) {
		return false
	}

	// If no crlType filter, applies to all CRLs
	if len(p.CRLType) == 0 {
		return true
	}

	// Check each crlType constraint
	for _, ct := range p.CRLType {
		ct = oid.NormalizeOID(ct)

		if ct == oid.DeltaCRLIndicator {
			if hasDeltaIndicator {
				return true
			}
			continue
		}

		if ct == "indirectCRL" {
			if isIndirectCRL {
				return true
			}
			continue
		}

		if ct == "completeCRL" {
			if !hasDeltaIndicator {
				return true
			}
			continue
		}
	}

	return false
}

// policyAppliesToCRLInput checks if a policy contains any CRL-related rules
func policyAppliesToCRLInput(p policy.Policy) bool {
	// If AppliesTo is explicitly set, use it
	if len(p.AppliesTo) > 0 {
		return slices.Contains(p.AppliesTo, AppliesToCRL)
	}

	// Check if any rule targets CRL
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

// hasDeltaCRLIndicator checks if CRL has the delta CRL indicator extension
func hasDeltaCRLIndicator(crl *x509.RevocationList) bool {
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

// isIndirectCRL checks if CRL is an indirect CRL (issued by different CA)
// Indirect CRL is indicated when the CRL issuer differs from the certificate issuer.
// This can be detected via the IssuingDistributionPoint extension's indirectCRL field.
func isIndirectCRL(crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}
	for _, ext := range crl.Extensions {
		if ext.Id.String() == oid.IssuingDistributionPoint {
			// The indirectCRL field is a boolean in the IssuingDistributionPoint extension
			// If the extension is present, we check the raw value for indirectCRL indicator
			// The ASN.1 structure includes an optional indirectCRL BOOLEAN DEFAULT FALSE
			// Parsing this requires decoding the extension value
			return checkIndirectCRLInExtension(ext.Value)
		}
	}
	return false
}

// checkIndirectCRLInExtension parses the IssuingDistributionPoint extension to find indirectCRL field
func checkIndirectCRLInExtension(extValue []byte) bool {
	// IssuingDistributionPoint ASN.1 structure (RFC 5280):
	// IssuingDistributionPoint ::= SEQUENCE {
	//   distributionPoint          [0] DistributionPointName OPTIONAL,
	//   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
	//   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
	//   onlySomeReasons            [3] ReasonFlags OPTIONAL,
	//   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
	//   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
	// }
	// We need to check if the [4] indirectCRL field is present and TRUE
	// The tag for indirectCRL is context-specific [4] which is 0x84 in DER
	for i := 0; i < len(extValue)-1; i++ {
		if extValue[i] == 0x84 { // context-specific tag [4] for indirectCRL
			// Next byte should be the length (typically 1 for BOOLEAN TRUE)
			if extValue[i+1] == 0x01 && i+2 < len(extValue) {
				return extValue[i+2] == 0xFF // TRUE in ASN.1 DER
			}
		}
	}
	return false
}

// filterPoliciesByInput returns policies that apply to the given input type
func filterPoliciesByInput(policies []policy.Policy, inputType string) []policy.Policy {
	var filtered []policy.Policy
	for _, p := range policies {
		if policyAppliesToInput(p, inputType) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// filterPoliciesByCert returns policies that apply to the given certificate
func filterPoliciesByCert(policies []policy.Policy, cert *x509.Certificate) []policy.Policy {
	var filtered []policy.Policy
	for _, p := range policies {
		if policyAppliesToCert(p, cert) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// filterPoliciesByCRL returns policies that apply to the given CRL
func filterPoliciesByCRL(policies []policy.Policy, hasDeltaIndicator bool, isIndirectCRL bool) []policy.Policy {
	var filtered []policy.Policy
	for _, p := range policies {
		if policyAppliesToCRL(p, hasDeltaIndicator, isIndirectCRL) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
