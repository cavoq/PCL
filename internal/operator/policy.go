package operator

import (
	"encoding/asn1"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/node"
)

var (
	oidPolicyMappings    = zasn1.ObjectIdentifier{2, 5, 29, 33}
	oidPolicyConstraints = zasn1.ObjectIdentifier{2, 5, 29, 36}
	oidInhibitAnyPolicy  = zasn1.ObjectIdentifier{2, 5, 29, 54}
	oidAnyPolicy         = asn1.ObjectIdentifier{2, 5, 29, 32, 0}
)

type CertificatePolicyValid struct{}

func (CertificatePolicyValid) Name() string { return "certificatePolicyValid" }

func (CertificatePolicyValid) Evaluate(_ *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if !ctx.HasCert() || !ctx.HasChain() {
		return false, nil
	}

	acceptablePolicies := make(map[string]bool)
	for _, op := range operands {
		if s, ok := op.(string); ok {
			acceptablePolicies[s] = true
		}
	}

	if len(acceptablePolicies) == 0 {
		return false, nil
	}

	validPolicies := make(map[string]bool)
	validPolicies[oidAnyPolicy.String()] = true

	requireExplicitPolicy := -1
	inhibitPolicyMapping := -1
	inhibitAnyPolicy := -1

	for i := len(ctx.Chain) - 1; i >= 0; i-- {
		cert := ctx.Chain[i].Cert
		if cert == nil {
			continue
		}

		pc := parsePolicyConstraints(cert)
		if pc.requireExplicitPolicy != nil && requireExplicitPolicy < 0 {
			requireExplicitPolicy = *pc.requireExplicitPolicy + i
		}
		if pc.inhibitPolicyMapping != nil && inhibitPolicyMapping < 0 {
			inhibitPolicyMapping = *pc.inhibitPolicyMapping + i
		}

		iap := parseInhibitAnyPolicy(cert)
		if iap != nil && inhibitAnyPolicy < 0 {
			inhibitAnyPolicy = *iap + i
		}

		certPolicies := make(map[string]bool)
		for _, oid := range cert.PolicyIdentifiers {
			certPolicies[oid.String()] = true
		}

		if inhibitAnyPolicy >= 0 && i <= inhibitAnyPolicy {
			delete(certPolicies, oidAnyPolicy.String())
		}

		if len(certPolicies) == 0 {
			validPolicies = make(map[string]bool)
		} else if validPolicies[oidAnyPolicy.String()] {
			validPolicies = certPolicies
		} else {
			newValid := make(map[string]bool)
			for p := range certPolicies {
				if validPolicies[p] || p == oidAnyPolicy.String() {
					newValid[p] = true
				}
			}
			validPolicies = newValid
		}

		if inhibitPolicyMapping < 0 || i > inhibitPolicyMapping {
			mappings := parsePolicyMappings(cert)
			for _, m := range mappings {
				if validPolicies[m.issuerPolicy] {
					validPolicies[m.subjectPolicy] = true
				}
			}
		}
	}

	if requireExplicitPolicy >= 0 && ctx.Cert.Position >= requireExplicitPolicy {
		delete(validPolicies, oidAnyPolicy.String())
	}

	for policy := range acceptablePolicies {
		if validPolicies[policy] || validPolicies[oidAnyPolicy.String()] {
			return true, nil
		}
	}

	return false, nil
}

type policyMapping struct {
	issuerPolicy  string
	subjectPolicy string
}

func parsePolicyMappings(cert *x509.Certificate) []policyMapping {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidPolicyMappings) {
			return decodePolicyMappings(ext.Value)
		}
	}
	return nil
}

func decodePolicyMappings(data []byte) []policyMapping {
	var seq []struct {
		IssuerDomain  asn1.ObjectIdentifier
		SubjectDomain asn1.ObjectIdentifier
	}
	if _, err := asn1.Unmarshal(data, &seq); err != nil {
		return nil
	}
	mappings := make([]policyMapping, 0, len(seq))
	for _, m := range seq {
		mappings = append(mappings, policyMapping{
			issuerPolicy:  m.IssuerDomain.String(),
			subjectPolicy: m.SubjectDomain.String(),
		})
	}
	return mappings
}

type policyConstraintsData struct {
	requireExplicitPolicy *int
	inhibitPolicyMapping  *int
}

func parsePolicyConstraints(cert *x509.Certificate) policyConstraintsData {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidPolicyConstraints) {
			return decodePolicyConstraints(ext.Value)
		}
	}
	return policyConstraintsData{}
}

func decodePolicyConstraints(data []byte) policyConstraintsData {
	var result policyConstraintsData
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(data, &seq)
	if err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence {
		return result
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var val asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &val)
		if err != nil {
			break
		}
		if val.Class == asn1.ClassContextSpecific {
			var n int
			if _, err := asn1.Unmarshal(val.FullBytes, &n); err == nil {
				switch val.Tag {
				case 0:
					result.requireExplicitPolicy = &n
				case 1:
					result.inhibitPolicyMapping = &n
				}
			}
		}
	}
	return result
}

func parseInhibitAnyPolicy(cert *x509.Certificate) *int {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidInhibitAnyPolicy) {
			var skipCerts int
			if _, err := asn1.Unmarshal(ext.Value, &skipCerts); err == nil {
				return &skipCerts
			}
		}
	}
	return nil
}
