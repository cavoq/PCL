package operator

import (
	stdasn1 "encoding/asn1"
	"strconv"
	"strings"
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/oid"
)

const (
	policyA = "1.2.3.4"
	policyB = "1.2.3.5"
	policyC = "1.2.3.6"
)

func TestCertificatePolicyValidNilContext(t *testing.T) {
	got, err := CertificatePolicyValid{}.Evaluate(nil, nil, []any{policyA})
	if err != nil || got {
		t.Fatalf("nil context = %v, %v; want false", got, err)
	}
}

func TestCertificatePolicyValidDefaultInputs(t *testing.T) {
	tests := []struct {
		name  string
		chain func() []*x509.Certificate // leaf first
		want  bool
	}{
		{
			name: "no policies and no constraints",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{policyTestCert("Leaf", "CA1"), policyTestCert("CA1", "Root"), policyTestRoot()}
			},
			want: true,
		},
		{
			name: "disjoint policies without requireExplicitPolicy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyB),
					policyTestCert("CA1", "Root", policyA),
					policyTestRoot(),
				}
			},
			want: true,
		},
		{
			name: "requireExplicitPolicy 0 with disjoint policies",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyB),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(0, -1)),
					policyTestRoot(),
				}
			},
			want: false,
		},
		{
			name: "requireExplicitPolicy 0 with a common policy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(0, -1)),
					policyTestRoot(),
				}
			},
			want: true,
		},
		{
			name: "requireExplicitPolicy 2 skips past a short path",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1"),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(2, -1)),
					policyTestRoot(),
				}
			},
			want: true,
		},
		{
			name: "requireExplicitPolicy 1 reaches the leaf",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1"),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(1, -1)),
					policyTestRoot(),
				}
			},
			want: false,
		},
		{
			name: "mapping to anyPolicy is invalid without operands",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyMappings, policyMappingsDER(policyA, oid.AnyPolicy)),
					policyTestRoot(),
				}
			},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CertificatePolicyValid{}.Evaluate(nil, policyChainContext(test.chain()...), nil)
			if err != nil || got != test.want {
				t.Fatalf("default inputs = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}

func TestCertificatePolicyValidPathProcessing(t *testing.T) {
	tests := []struct {
		name       string
		chain      func() []*x509.Certificate // leaf first
		acceptable []any
		want       bool
	}{
		{
			name: "same policy through the path",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					policyTestCert("CA1", "Root", policyA),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "anyPolicy issuer accepts the leaf policy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					policyTestCert("CA1", "Root", oid.AnyPolicy),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "anyPolicy leaf satisfies an acceptable policy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", oid.AnyPolicy),
					policyTestCert("CA1", "Root", oid.AnyPolicy),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "policy not asserted by the intermediate",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					policyTestCert("CA1", "Root", policyB),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       false,
		},
		{
			name: "valid policy outside the acceptable set",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					policyTestCert("CA1", "Root", policyA),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyB},
			want:       false,
		},
		{
			name: "one of several acceptable policies",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyB),
					policyTestCert("CA1", "Root", policyB),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA, policyB},
			want:       true,
		},
		{
			name: "certificate without policies",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1"),
					policyTestCert("CA1", "Root", policyA),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       false,
		},
		{
			name: "trust anchor policies are not processed",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					policyTestCert("CA1", "Root", policyA),
					policyTestRoot(policyC),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "policy mapping keeps the issuer domain policy valid",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyB),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyMappings, policyMappingsDER(policyA, policyB)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "mapped subject domain policy is not in the user domain",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyB),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyMappings, policyMappingsDER(policyA, policyB)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyB},
			want:       false,
		},
		{
			name: "inhibitPolicyMapping 0 deletes the mapped policy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA2", policyB),
					withPolicyExtension(policyTestCert("CA2", "CA1", policyA),
						oid.PolicyMappings, policyMappingsDER(policyA, policyB)),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(-1, 0)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       false,
		},
		{
			name: "inhibitPolicyMapping 1 still allows the next mapping",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA2", policyB),
					withPolicyExtension(policyTestCert("CA2", "CA1", policyA),
						oid.PolicyMappings, policyMappingsDER(policyA, policyB)),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(-1, 1)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "inhibitAnyPolicy 0 stops later anyPolicy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA2", policyA),
					policyTestCert("CA2", "CA1", oid.AnyPolicy),
					withPolicyExtension(policyTestCert("CA1", "Root", oid.AnyPolicy),
						oid.InhibitAnyPolicy, inhibitAnyPolicyDER(0)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       false,
		},
		{
			name: "anyPolicy chain without inhibitAnyPolicy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA2", policyA),
					policyTestCert("CA2", "CA1", oid.AnyPolicy),
					policyTestCert("CA1", "Root", oid.AnyPolicy),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "requireExplicitPolicy does not change an explicit check",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyConstraints, policyConstraintsDER(0, -1)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       true,
		},
		{
			name: "mapping anyPolicy is invalid",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyMappings, policyMappingsDER(oid.AnyPolicy, policyA)),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       false,
		},
		{
			name: "malformed policy mappings fail",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyA),
					withPolicyExtension(policyTestCert("CA1", "Root", policyA),
						oid.PolicyMappings, []byte{0x30, 0x01}),
					policyTestRoot(),
				}
			},
			acceptable: []any{policyA},
			want:       false,
		},
		{
			name: "anyPolicy operand accepts any valid policy",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{
					policyTestCert("Leaf", "CA1", policyC),
					policyTestCert("CA1", "Root", policyC),
					policyTestRoot(),
				}
			},
			acceptable: []any{oid.AnyPolicy},
			want:       true,
		},
		{
			name: "trust anchor evaluated on its own",
			chain: func() []*x509.Certificate {
				return []*x509.Certificate{policyTestRoot(policyA)}
			},
			acceptable: []any{policyA},
			want:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CertificatePolicyValid{}.Evaluate(nil, policyChainContext(test.chain()...), test.acceptable)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != test.want {
				t.Fatalf("Evaluate = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCertificatePolicyValidEvaluatesPathToIntermediate(t *testing.T) {
	leaf := policyTestCert("Leaf", "CA1", policyB)
	intermediate := policyTestCert("CA1", "Root", policyA)
	ctx := policyChainContext(leaf, intermediate, policyTestRoot())
	ctx.Cert = ctx.Chain[1]

	got, err := CertificatePolicyValid{}.Evaluate(nil, ctx, []any{policyA})
	if err != nil || !got {
		t.Fatalf("intermediate path = %v, %v; want true", got, err)
	}
}

func TestCertificatePolicyValidRejectsDuplicateExtensionsRegardlessOfOrder(t *testing.T) {
	first := pkix.Extension{
		Id:    asn1.ObjectIdentifier(dottedOID(oid.CertificatePolicies)),
		Value: certificatePoliciesDER(policyA),
	}
	second := pkix.Extension{
		Id:    asn1.ObjectIdentifier(dottedOID(oid.CertificatePolicies)),
		Value: certificatePoliciesDER(policyB),
	}
	for index, extensions := range [][]pkix.Extension{{first, second}, {second, first}} {
		certificate := policyTestRoot()
		certificate.Extensions = extensions
		got, err := CertificatePolicyValid{}.Evaluate(
			nil,
			policyChainContext(certificate),
			[]any{policyA},
		)
		if err != nil {
			t.Fatalf("extension order %d: Evaluate: %v", index, err)
		}
		if got {
			t.Fatalf("extension order %d accepted duplicate CertificatePolicies", index)
		}
	}
}

func policyTestRoot(policies ...string) *x509.Certificate {
	return policyTestCert("Root", "Root", policies...)
}

func policyTestCert(subject, issuer string, policies ...string) *x509.Certificate {
	certificate := &x509.Certificate{
		Subject: pkix.Name{CommonName: subject},
		Issuer:  pkix.Name{CommonName: issuer},
	}
	for _, policy := range policies {
		certificate.PolicyIdentifiers = append(certificate.PolicyIdentifiers, asn1.ObjectIdentifier(dottedOID(policy)))
	}
	return certificate
}

func withPolicyExtension(certificate *x509.Certificate, identifier string, value []byte) *x509.Certificate {
	certificate.Extensions = append(certificate.Extensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier(dottedOID(identifier)),
		Value: value,
	})
	return certificate
}

// policyChainContext evaluates the first certificate of a leaf-first chain.
func policyChainContext(chain ...*x509.Certificate) *EvaluationContext {
	infos := make([]*cert.Info, 0, len(chain))
	for _, certificate := range chain {
		infos = append(infos, &cert.Info{Cert: certificate})
	}
	return &EvaluationContext{Cert: infos[0], Chain: infos}
}

func policyMappingsDER(issuerDomainPolicy, subjectDomainPolicy string) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(mappings *cryptobyte.Builder) {
		mappings.AddASN1(cryptobyte_asn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			mapping.AddASN1ObjectIdentifier(dottedOID(issuerDomainPolicy))
			mapping.AddASN1ObjectIdentifier(dottedOID(subjectDomainPolicy))
		})
	})
	return builder.BytesOrPanic()
}

func certificatePoliciesDER(policies ...string) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(policyInfos *cryptobyte.Builder) {
		for _, policy := range policies {
			policy := policy
			policyInfos.AddASN1(cryptobyte_asn1.SEQUENCE, func(policyInfo *cryptobyte.Builder) {
				policyInfo.AddASN1ObjectIdentifier(dottedOID(policy))
			})
		}
	})
	return builder.BytesOrPanic()
}

// policyConstraintsDER omits a field whose value is negative.
func policyConstraintsDER(requireExplicitPolicy, inhibitPolicyMapping int) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(constraints *cryptobyte.Builder) {
		if requireExplicitPolicy >= 0 {
			constraints.AddASN1Int64WithTag(int64(requireExplicitPolicy), cryptobyte_asn1.Tag(0).ContextSpecific())
		}
		if inhibitPolicyMapping >= 0 {
			constraints.AddASN1Int64WithTag(int64(inhibitPolicyMapping), cryptobyte_asn1.Tag(1).ContextSpecific())
		}
	})
	return builder.BytesOrPanic()
}

func inhibitAnyPolicyDER(skipCerts int) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1Int64(int64(skipCerts))
	return builder.BytesOrPanic()
}

func dottedOID(dotted string) stdasn1.ObjectIdentifier {
	parts := strings.Split(dotted, ".")
	identifier := make(stdasn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		arc, err := strconv.Atoi(part)
		if err != nil {
			panic(err)
		}
		identifier = append(identifier, arc)
	}
	return identifier
}
