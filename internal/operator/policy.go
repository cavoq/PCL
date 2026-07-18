package operator

import (
	"encoding/asn1"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
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
	validPolicies[oid.AnyPolicy] = true

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
		for _, policyID := range cert.PolicyIdentifiers {
			certPolicies[policyID.String()] = true
		}

		if inhibitAnyPolicy >= 0 && i <= inhibitAnyPolicy {
			delete(certPolicies, oid.AnyPolicy)
		}

		if len(certPolicies) == 0 {
			validPolicies = make(map[string]bool)
		} else if validPolicies[oid.AnyPolicy] {
			validPolicies = certPolicies
		} else {
			newValid := make(map[string]bool)
			for p := range certPolicies {
				if validPolicies[p] || p == oid.AnyPolicy {
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
		delete(validPolicies, oid.AnyPolicy)
	}

	for policy := range acceptablePolicies {
		if validPolicies[policy] || validPolicies[oid.AnyPolicy] {
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
		if ext.Id.String() == oid.PolicyMappings {
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
		if ext.Id.String() == oid.PolicyConstraints {
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
		if ext.Id.String() == oid.InhibitAnyPolicy {
			var skipCerts int
			if _, err := asn1.Unmarshal(ext.Value, &skipCerts); err == nil {
				return &skipCerts
			}
		}
	}
	return nil
}
