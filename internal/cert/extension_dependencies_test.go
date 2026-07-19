package cert

import (
	stdasn1 "encoding/asn1"
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestBasicConstraintsDependenciesValid(t *testing.T) {
	withPathLen := func() *x509.Certificate {
		return &x509.Certificate{
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
		}
	}

	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "nil"},
		{name: "no path length", certificate: &x509.Certificate{}, want: true},
		{
			name: "path length requires CA",
			certificate: &x509.Certificate{
				MaxPathLenZero: true,
				Extensions:     []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)},
				KeyUsage:       x509.KeyUsageCertSign,
			},
		},
		{name: "path length requires Key Usage", certificate: withPathLen()},
		{
			name: "path length requires keyCertSign",
			certificate: func() *x509.Certificate {
				certificate := withPathLen()
				certificate.Extensions = []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)}
				certificate.KeyUsage = x509.KeyUsageCRLSign
				return certificate
			}(),
		},
		{
			name: "complete dependencies",
			certificate: func() *x509.Certificate {
				certificate := withPathLen()
				certificate.Extensions = []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)}
				certificate.KeyUsage = x509.KeyUsageCertSign
				return certificate
			}(),
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := BasicConstraintsDependenciesValid(test.certificate); got != test.want {
				t.Fatalf("BasicConstraintsDependenciesValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBasicConstraintsDependenciesUseStrictRawPresenceAndCAValue(t *testing.T) {
	pathWithoutCA := extensionForCertificateTest(oid.BasicConstraints)
	pathWithoutCA.Value = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	certificate := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		Extensions: []pkix.Extension{
			pathWithoutCA,
			extensionForCertificateTest(oid.KeyUsage),
		},
	}
	if BasicConstraintsDependenciesValid(certificate) {
		t.Fatal("typed CA value hid a raw pathLenConstraint without cA true")
	}
}

func TestKeyUsageDependenciesValid(t *testing.T) {
	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "nil"},
		{name: "extension absent", certificate: &x509.Certificate{}, want: true},
		{
			name: "keyCertSign requires CA",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)},
				KeyUsage:   x509.KeyUsageCertSign,
			},
		},
		{
			name: "keyCertSign on CA",
			certificate: &x509.Certificate{
				Extensions:            []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)},
				KeyUsage:              x509.KeyUsageCertSign,
				BasicConstraintsValid: true,
				IsCA:                  true,
			},
			want: true,
		},
		{
			name: "encipherOnly without keyAgreement has undefined semantics but is permitted",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)},
				KeyUsage:   x509.KeyUsageEncipherOnly,
			},
			want: true,
		},
		{
			name: "decipherOnly with keyAgreement",
			certificate: &x509.Certificate{
				Extensions: []pkix.Extension{extensionForCertificateTest(oid.KeyUsage)},
				KeyUsage:   x509.KeyUsageKeyAgreement | x509.KeyUsageDecipherOnly,
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := KeyUsageDependenciesValid(test.certificate); got != test.want {
				t.Fatalf("KeyUsageDependenciesValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCAOnlyExtensionDependencies(t *testing.T) {
	predicates := []struct {
		name       string
		identifier string
		check      func(*x509.Certificate) bool
	}{
		{name: "name constraints", identifier: oid.NameConstraints, check: NameConstraintsDependenciesValid},
		{name: "policy constraints", identifier: oid.PolicyConstraints, check: PolicyConstraintsDependenciesValid},
		{name: "inhibit anyPolicy", identifier: oid.InhibitAnyPolicy, check: InhibitAnyPolicyDependenciesValid},
	}

	for _, predicate := range predicates {
		t.Run(predicate.name, func(t *testing.T) {
			if predicate.check(nil) {
				t.Fatal("nil certificate passed")
			}
			if !predicate.check(&x509.Certificate{}) {
				t.Fatal("absent extension failed")
			}
			leaf := &x509.Certificate{Extensions: []pkix.Extension{
				extensionForCertificateTest(predicate.identifier),
			}}
			if predicate.check(leaf) {
				t.Fatal("extension on end entity passed")
			}
			leaf.BasicConstraintsValid = true
			leaf.IsCA = true
			if !predicate.check(leaf) {
				t.Fatal("extension on CA failed")
			}

			rawCA := &x509.Certificate{Extensions: []pkix.Extension{
				extensionForCertificateTest(predicate.identifier),
				{
					Id:    oidForCertificateTest(t, oid.BasicConstraints),
					Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
				},
			}}
			if !predicate.check(rawCA) {
				t.Fatal("extension on CA represented only by strict raw facts failed")
			}
		})
	}
}

func TestNameConstraintsDistancesValid(t *testing.T) {
	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "nil"},
		{name: "absent", certificate: &x509.Certificate{}, want: true},
		{
			name:        "default minimum and absent maximum",
			certificate: certificateWithExtension(oid.NameConstraints, nameConstraintsForTest(nil, nil)),
			want:        true,
		},
		{
			name:        "nonzero minimum",
			certificate: certificateWithExtension(oid.NameConstraints, nameConstraintsForTest(pointerTo(1), nil)),
		},
		{
			name:        "present maximum",
			certificate: certificateWithExtension(oid.NameConstraints, nameConstraintsForTest(nil, pointerTo(1))),
		},
		{
			name:        "malformed",
			certificate: certificateWithExtension(oid.NameConstraints, []byte{0x30, 0x00}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NameConstraintsDistancesValid(test.certificate); got != test.want {
				t.Fatalf("NameConstraintsDistancesValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCRLDistributionPointsDependenciesValid(t *testing.T) {
	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "nil"},
		{name: "absent", certificate: &x509.Certificate{}, want: true},
		{
			name: "one point covers all reasons",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{}),
			),
			want: true,
		},
		{
			name: "every point has a reason subset",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{reasons: true}),
			),
		},
		{
			name: "one point explicitly covers every defined reason",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{
					reasonFlags: []byte{0x07, 0x7f, 0x80},
				}),
			),
			want: true,
		},
		{
			name: "unused reason bit is invalid",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{
					reasonFlags: []byte{0x07, 0xff, 0x80},
				}),
			),
		},
		{
			name: "one of multiple points covers all reasons",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(
					crlDistributionPointForTest{reasons: true},
					crlDistributionPointForTest{},
				),
			),
			want: true,
		},
		{
			name: "cRLIssuer must use directoryName",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{issuerTags: []int{2}}),
			),
		},
		{
			name: "directoryName cRLIssuer",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{issuerTags: []int{4}}),
			),
			want: true,
		},
		{
			name: "cRLIssuer rejects multiple issuer DNs",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{issuerTags: []int{4, 4}}),
			),
		},
		{
			name: "relative name accepts one issuer DN",
			certificate: certificateWithExtension(
				oid.CRLDistributionPoints,
				crlDistributionPointsForTest(crlDistributionPointForTest{
					relative:   true,
					issuerTags: []int{4},
				}),
			),
			want: true,
		},
		{
			name:        "malformed",
			certificate: certificateWithExtension(oid.CRLDistributionPoints, []byte{0x30, 0x00}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CRLDistributionPointsDependenciesValid(test.certificate); got != test.want {
				t.Fatalf("CRLDistributionPointsDependenciesValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPolicyMappingsDependenciesValid(t *testing.T) {
	validMappings := marshalPolicyMappingsForTest(t, [][2]string{{"1.2.3.1", "1.2.3.2"}})
	issuerAny := marshalPolicyMappingsForTest(t, [][2]string{{oid.AnyPolicy, "1.2.3.2"}})
	subjectAny := marshalPolicyMappingsForTest(t, [][2]string{{"1.2.3.1", oid.AnyPolicy}})

	tests := []struct {
		name        string
		certificate *x509.Certificate
		want        bool
	}{
		{name: "nil"},
		{name: "absent", certificate: &x509.Certificate{}, want: true},
		{name: "end entity", certificate: certificateWithPolicyMappings(validMappings)},
		{
			name:        "malformed",
			certificate: caWithPolicyMappings([]byte{0x30, 0x00}),
		},
		{name: "issuer anyPolicy", certificate: caWithPolicyMappings(issuerAny)},
		{name: "subject anyPolicy", certificate: caWithPolicyMappings(subjectAny)},
		{name: "valid", certificate: caWithPolicyMappings(validMappings), want: true},
		{
			name: "valid on CA represented only by strict raw facts",
			certificate: func() *x509.Certificate {
				certificate := certificateWithPolicyMappings(validMappings)
				certificate.Extensions = append(certificate.Extensions, pkix.Extension{
					Id:    oidForCertificateTest(t, oid.BasicConstraints),
					Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
				})
				return certificate
			}(),
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := PolicyMappingsDependenciesValid(test.certificate); got != test.want {
				t.Fatalf("PolicyMappingsDependenciesValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPolicyMappingsIssuerPoliciesPresent(t *testing.T) {
	value := marshalPolicyMappingsForTest(t, [][2]string{
		{"1.2.3.1", "1.2.3.2"},
		{"1.2.3.3", "1.2.3.4"},
	})
	certificate := caWithPolicyMappings(value)
	certificate.Extensions = append(certificate.Extensions, pkix.Extension{
		Id: oidForCertificateTest(t, oid.CertificatePolicies),
		Value: marshalCertificatePoliciesForTest(t, []string{
			"1.2.3.1",
			"1.2.3.3",
		}),
	})
	if !PolicyMappingsIssuerPoliciesPresent(certificate) {
		t.Fatal("all issuer policies were present but predicate failed")
	}

	certificate.Extensions[len(certificate.Extensions)-1].Value = marshalCertificatePoliciesForTest(
		t,
		[]string{"1.2.3.1"},
	)
	if PolicyMappingsIssuerPoliciesPresent(certificate) {
		t.Fatal("missing issuer policy passed")
	}

	certificate.PolicyIdentifiers = []zasn1.ObjectIdentifier{
		oidForCertificateTest(t, "1.2.3.1"),
		oidForCertificateTest(t, "1.2.3.3"),
	}
	certificate.Extensions[len(certificate.Extensions)-1].Value = []byte{0x30, 0x00}
	if PolicyMappingsIssuerPoliciesPresent(certificate) {
		t.Fatal("malformed raw CertificatePolicies passed through typed policy identifiers")
	}
}

func certificateWithPolicyMappings(value []byte) *x509.Certificate {
	return certificateWithExtension(oid.PolicyMappings, value)
}

func caWithPolicyMappings(value []byte) *x509.Certificate {
	certificate := certificateWithPolicyMappings(value)
	certificate.BasicConstraintsValid = true
	certificate.IsCA = true
	return certificate
}

func marshalPolicyMappingsForTest(t *testing.T, mappings [][2]string) []byte {
	t.Helper()
	type policyMapping struct {
		IssuerDomainPolicy  stdasn1.ObjectIdentifier
		SubjectDomainPolicy stdasn1.ObjectIdentifier
	}
	decoded := make([]policyMapping, 0, len(mappings))
	for _, mapping := range mappings {
		issuer, err := oid.Parse(mapping[0])
		if err != nil {
			t.Fatalf("parse issuer policy: %v", err)
		}
		subject, err := oid.Parse(mapping[1])
		if err != nil {
			t.Fatalf("parse subject policy: %v", err)
		}
		decoded = append(decoded, policyMapping{issuer, subject})
	}
	value, err := stdasn1.Marshal(decoded)
	if err != nil {
		t.Fatalf("marshal policy mappings: %v", err)
	}
	return value
}

func marshalCertificatePoliciesForTest(t *testing.T, identifiers []string) []byte {
	t.Helper()
	type policyInformation struct {
		PolicyIdentifier stdasn1.ObjectIdentifier
	}
	policies := make([]policyInformation, 0, len(identifiers))
	for _, identifier := range identifiers {
		parsed, err := oid.Parse(identifier)
		if err != nil {
			t.Fatalf("parse certificate policy: %v", err)
		}
		policies = append(policies, policyInformation{PolicyIdentifier: parsed})
	}
	value, err := stdasn1.Marshal(policies)
	if err != nil {
		t.Fatalf("marshal certificate policies: %v", err)
	}
	return value
}

func certificateWithExtension(identifier string, value []byte) *x509.Certificate {
	extension := extensionForCertificateTest(identifier)
	extension.Value = value
	return &x509.Certificate{Extensions: []pkix.Extension{extension}}
}

func nameConstraintsForTest(minimum, maximum *int) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(builder *cryptobyte.Builder) {
					builder.AddBytes([]byte(".example.test"))
				})
				if minimum != nil {
					builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific(), func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte{byte(*minimum)})
					})
				}
				if maximum != nil {
					builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte{byte(*maximum)})
					})
				}
			})
		})
	})
	return builder.BytesOrPanic()
}

type crlDistributionPointForTest struct {
	relative    bool
	reasons     bool
	reasonFlags []byte
	issuerTags  []int
}

func crlDistributionPointsForTest(points ...crlDistributionPointForTest) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		for _, point := range points {
			point := point
			builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
					if point.relative {
						builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
							builder.AddBytes(relativeNameContentsForTest())
						})
						return
					}
					builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
						builder.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(builder *cryptobyte.Builder) {
							builder.AddBytes([]byte("http://crl.example.test/root.crl"))
						})
					})
				})
				if point.reasons || point.reasonFlags != nil {
					builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(builder *cryptobyte.Builder) {
						if point.reasonFlags != nil {
							builder.AddBytes(point.reasonFlags)
							return
						}
						builder.AddBytes([]byte{0x06, 0x40})
					})
				}
				if len(point.issuerTags) > 0 {
					builder.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
						for _, tag := range point.issuerTags {
							switch tag {
							case 4:
								builder.AddASN1(cryptobyte_asn1.Tag(4).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
									builder.AddBytes(distinguishedNameForTest())
								})
							default:
								builder.AddASN1(cryptobyte_asn1.Tag(tag).ContextSpecific(), func(builder *cryptobyte.Builder) {
									builder.AddBytes([]byte("issuer.example.test"))
								})
							}
						}
					})
				}
			})
		}
	})
	return builder.BytesOrPanic()
}

func relativeNameContentsForTest() []byte {
	return []byte{0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 0x78}
}

func distinguishedNameForTest() []byte {
	return []byte{0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 0x78}
}

func pointerTo(value int) *int {
	return &value
}
