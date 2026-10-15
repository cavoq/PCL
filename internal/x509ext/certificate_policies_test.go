package x509ext

import (
	stdasn1 "encoding/asn1"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestDecodeCertificatePoliciesQualifiers(t *testing.T) {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(policies *cryptobyte.Builder) {
		policies.AddASN1(cryptobyte_asn1.SEQUENCE, func(policy *cryptobyte.Builder) {
			policy.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 23, 140, 1, 2, 1})
			policy.AddASN1(cryptobyte_asn1.SEQUENCE, func(qualifiers *cryptobyte.Builder) {
				addBoundaryPolicyQualifier(
					qualifiers,
					stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
					func(value *cryptobyte.Builder) {
						value.AddASN1(cryptobyte_asn1.IA5String, func(uri *cryptobyte.Builder) {
							uri.AddBytes([]byte("https://cps.example.test/policy"))
						})
					},
				)
				addBoundaryPolicyQualifier(
					qualifiers,
					stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2},
					func(value *cryptobyte.Builder) {
						value.AddASN1(cryptobyte_asn1.SEQUENCE, func(notice *cryptobyte.Builder) {
							notice.AddASN1(cryptobyte_asn1.SEQUENCE, func(reference *cryptobyte.Builder) {
								reference.AddASN1(cryptobyte_asn1.UTF8String, func(organization *cryptobyte.Builder) {
									organization.AddBytes([]byte("Example CA"))
								})
								reference.AddASN1(cryptobyte_asn1.SEQUENCE, func(numbers *cryptobyte.Builder) {
									numbers.AddASN1Int64(1)
									numbers.AddASN1Int64(7)
								})
							})
							notice.AddASN1(cryptobyte_asn1.Tag(26), func(text *cryptobyte.Builder) {
								text.AddBytes([]byte("Terms apply"))
							})
						})
					},
				)
			})
		})
		policies.AddASN1(cryptobyte_asn1.SEQUENCE, func(policy *cryptobyte.Builder) {
			policy.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{1, 2, 3, 4})
			policy.AddASN1(cryptobyte_asn1.SEQUENCE, func(qualifiers *cryptobyte.Builder) {
				addBoundaryPolicyQualifier(
					qualifiers,
					stdasn1.ObjectIdentifier{1, 2, 3, 5},
					func(value *cryptobyte.Builder) { value.AddASN1Int64(9) },
				)
			})
		})
	})
	der := builder.BytesOrPanic()
	decoded, err := DecodeCertificatePolicies(der)
	if err != nil {
		t.Fatalf("DecodeCertificatePolicies() error = %v", err)
	}
	if len(decoded.Policies) != 2 || len(decoded.Policies[0].Qualifiers) != 2 ||
		decoded.Policies[0].Qualifiers[0].Kind != PolicyQualifierCPS ||
		decoded.Policies[0].Qualifiers[0].CPSURI != "https://cps.example.test/policy" ||
		decoded.Policies[1].Qualifiers[0].Kind != PolicyQualifierUnknown {
		t.Fatalf("certificate policies = %#v", decoded)
	}
	notice := decoded.Policies[0].Qualifiers[1].UserNotice
	if notice == nil || notice.Reference == nil || notice.Reference.Organization.Value != "Example CA" ||
		!slices.Equal(notice.Reference.Numbers, []int64{1, 7}) || notice.ExplicitText == nil ||
		notice.ExplicitText.Value != "Terms apply" {
		t.Fatalf("user notice = %#v", notice)
	}
	identifiers, err := DecodeCertificatePolicyIdentifiersStrict(der)
	if err != nil || !slices.Equal(identifiers, []string{"2.23.140.1.2.1", "1.2.3.4"}) {
		t.Fatalf("policy identifiers = %q, %v", identifiers, err)
	}
}

func TestDecodeCertificatePoliciesRejectsDuplicatesAndMalformedDER(t *testing.T) {
	policy := boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3, 4}, nil)
	duplicate := boundaryCertificatePolicies(policy, policy)
	anyWithUnknown := boundaryPolicyInformation(
		stdasn1.ObjectIdentifier{2, 5, 29, 32, 0},
		boundaryPolicyQualifiers(boundaryPolicyQualifier(
			stdasn1.ObjectIdentifier{1, 2, 3, 5},
			[]byte{0x02, 0x01, 0x01},
		)),
	)

	malformed := map[string][]byte{
		"absent value":             nil,
		"empty policies":           {0x30, 0x00},
		"wrong policy tag":         {0x30, 0x03, 0x02, 0x01, 0x00},
		"missing policy OID":       {0x30, 0x04, 0x30, 0x02, 0x05, 0x00},
		"empty qualifiers":         boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, []byte{0x30, 0x00})),
		"qualifiers wrong tag":     boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, []byte{0x31, 0x00})),
		"duplicate policy":         duplicate,
		"unknown on anyPolicy":     boundaryCertificatePolicies(anyWithUnknown),
		"qualifier wrong tag":      boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers([]byte{0x02, 0x01, 0x00}))),
		"qualifier missing OID":    boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers([]byte{0x30, 0x02, 0x05, 0x00}))),
		"qualifier missing value":  boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 2, 3}, nil)))),
		"CPS wrong value tag":      boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}, []byte{0x0c, 0x01, 'x'})))),
		"CPS empty":                boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}, []byte{0x16, 0x00})))),
		"CPS non IA5":              boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}, []byte{0x16, 0x01, 0xff})))),
		"user notice wrong tag":    boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}, []byte{0x05, 0x00})))),
		"empty explicit text":      boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}, []byte{0x30, 0x02, 0x0c, 0x00})))),
		"unsupported display text": boundaryCertificatePolicies(boundaryPolicyInformation(stdasn1.ObjectIdentifier{1, 2, 3}, boundaryPolicyQualifiers(boundaryPolicyQualifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}, []byte{0x30, 0x03, 0x02, 0x01, 0x01})))),
		"trailing data":            append(boundaryCertificatePolicies(policy), 0),
	}
	for name, der := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCertificatePolicies(der); err == nil {
				t.Fatalf("DecodeCertificatePolicies(%x) accepted malformed DER", der)
			}
		})
	}
}

func addBoundaryPolicyQualifier(
	builder *cryptobyte.Builder,
	identifier stdasn1.ObjectIdentifier,
	addValue func(*cryptobyte.Builder),
) {
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(qualifier *cryptobyte.Builder) {
		qualifier.AddASN1ObjectIdentifier(identifier)
		addValue(qualifier)
	})
}

func boundaryCertificatePolicies(policies ...[]byte) []byte {
	return boundarySequence(policies...)
}

func boundaryPolicyInformation(identifier stdasn1.ObjectIdentifier, qualifiers []byte) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(policy *cryptobyte.Builder) {
		policy.AddASN1ObjectIdentifier(identifier)
		policy.AddBytes(qualifiers)
	})
	return builder.BytesOrPanic()
}

func boundaryPolicyQualifiers(qualifiers ...[]byte) []byte {
	return boundarySequence(qualifiers...)
}

func boundaryPolicyQualifier(identifier stdasn1.ObjectIdentifier, value []byte) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(qualifier *cryptobyte.Builder) {
		qualifier.AddASN1ObjectIdentifier(identifier)
		qualifier.AddBytes(value)
	})
	return builder.BytesOrPanic()
}

func boundarySequence(elements ...[]byte) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(sequence *cryptobyte.Builder) {
		for _, element := range elements {
			sequence.AddBytes(element)
		}
	})
	return builder.BytesOrPanic()
}
