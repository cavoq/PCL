package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	testDVPolicyOID         = stdasn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	testCPSOID              = stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	testUserNoticeOID       = stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
	testUnknownQualifierOID = stdasn1.ObjectIdentifier{1, 2, 3, 4}
)

func buildCertificatePolicyFixture(addQualifiers func(*cryptobyte.Builder)) []byte {
	return buildCertificatePolicyFixtureForOID(testDVPolicyOID, addQualifiers)
}

func buildCertificatePolicyFixtureForOID(
	policyOID stdasn1.ObjectIdentifier,
	addQualifiers func(*cryptobyte.Builder),
) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
			builder.AddASN1ObjectIdentifier(policyOID)
			if addQualifiers != nil {
				builder.AddASN1(cryptobyte_asn1.SEQUENCE, addQualifiers)
			}
		})
	})
	return builder.BytesOrPanic()
}

func buildCertificatePoliciesWithIdentifiers(identifiers ...stdasn1.ObjectIdentifier) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(policies *cryptobyte.Builder) {
		for _, identifier := range identifiers {
			policies.AddASN1(cryptobyte_asn1.SEQUENCE, func(policy *cryptobyte.Builder) {
				policy.AddASN1ObjectIdentifier(identifier)
			})
		}
	})
	return builder.BytesOrPanic()
}

func addPolicyQualifierFixture(
	builder *cryptobyte.Builder,
	qualifierOID stdasn1.ObjectIdentifier,
	addValue func(*cryptobyte.Builder),
) {
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1ObjectIdentifier(qualifierOID)
		addValue(builder)
	})
}

func requirePolicyChild(t *testing.T, parent *node.Node, name string) *node.Node {
	t.Helper()
	child, ok := parent.Children[name]
	if !ok {
		t.Fatalf("node %q has no child %q", parent.Name, name)
	}
	return child
}

func TestCertificatePoliciesDetailedNodeSchema(t *testing.T) {
	unknownRaw := []byte{0xde, 0xad, 0xbe, 0xef}
	der := buildCertificatePolicyFixture(func(builder *cryptobyte.Builder) {
		addPolicyQualifierFixture(builder, testCPSOID, func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.IA5String, func(builder *cryptobyte.Builder) {
				builder.AddBytes([]byte("https://example.test/cps"))
			})
		})
		addPolicyQualifierFixture(builder, testUserNoticeOID, func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
					builder.AddASN1(cryptobyte_asn1.UTF8String, func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte("Example CA"))
					})
					builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
						builder.AddASN1Int64(7)
						builder.AddASN1Int64(11)
					})
				})
				builder.AddASN1(cryptobyte_asn1.Tag(26), func(builder *cryptobyte.Builder) {
					builder.AddBytes([]byte("Read this notice"))
				})
			})
		})
		addPolicyQualifierFixture(builder, testUnknownQualifierOID, func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.OCTET_STRING, func(builder *cryptobyte.Builder) {
				builder.AddBytes(unknownRaw)
			})
		})
	})

	root, err := ParseCertPoliciesStrict(der)
	if err != nil {
		t.Fatalf("ParseCertPoliciesStrict: %v", err)
	}
	if raw, ok := root.Children["raw"].Value.([]byte); !ok || !bytes.Equal(raw, der) {
		t.Fatalf("CertificatePolicies raw = %#v, want %x", root.Children["raw"], der)
	}
	policy := requirePolicyChild(t, requirePolicyChild(t, root, "policyInformations"), "0")
	if root.Children[oid.CABFDomainValidatedPolicy] != policy || root.Children["dvPolicy"] != policy {
		t.Fatal("policy OID and friendly-name aliases do not share the indexed policy node")
	}
	if unprocessed := root.Children["unprocessed"]; unprocessed == nil || unprocessed.Value != true {
		t.Fatal("unknown policy qualifier did not mark CertificatePolicies unprocessed")
	}
	if got := requirePolicyChild(t, policy, "policyIdentifier").Value; got != oid.CABFDomainValidatedPolicy {
		t.Errorf("policyIdentifier = %v, want %s", got, oid.CABFDomainValidatedPolicy)
	}
	if got := requirePolicyChild(t, policy, "name").Value; got != "dvPolicy" {
		t.Errorf("policy name = %v, want dvPolicy", got)
	}

	qualifiers := requirePolicyChild(t, policy, "policyQualifiers")
	if got := requirePolicyChild(t, qualifiers, "count").Value; got != 3 {
		t.Errorf("qualifier count = %v, want 3", got)
	}
	cps := requirePolicyChild(t, qualifiers, "0")
	if qualifiers.Children[oid.PolicyQualifierCPS] != cps {
		t.Fatal("CPS OID alias does not share the indexed qualifier node")
	}
	for child, want := range map[string]any{
		"type":     "cps",
		"encoding": "ia5String",
		"cpsURI":   "https://example.test/cps",
		"scheme":   "https",
	} {
		if got := requirePolicyChild(t, cps, child).Value; got != want {
			t.Errorf("CPS %s = %v, want %v", child, got, want)
		}
	}

	userNotice := requirePolicyChild(t, requirePolicyChild(t, qualifiers, "1"), "userNotice")
	reference := requirePolicyChild(t, userNotice, "noticeReference")
	organization := requirePolicyChild(t, reference, "organization")
	if got := requirePolicyChild(t, organization, "value").Value; got != "Example CA" {
		t.Errorf("organization = %v, want Example CA", got)
	}
	if got := requirePolicyChild(t, organization, "encoding").Value; got != "utf8String" {
		t.Errorf("organization encoding = %v, want utf8String", got)
	}
	numbers := requirePolicyChild(t, reference, "noticeNumbers")
	if requirePolicyChild(t, numbers, "0").Value != int64(7) ||
		requirePolicyChild(t, numbers, "1").Value != int64(11) ||
		requirePolicyChild(t, numbers, "count").Value != 2 {
		t.Errorf("notice numbers were not preserved: %#v", numbers.Children)
	}
	explicitText := requirePolicyChild(t, userNotice, "explicitText")
	if requirePolicyChild(t, explicitText, "value").Value != "Read this notice" ||
		requirePolicyChild(t, explicitText, "encoding").Value != "visibleString" ||
		requirePolicyChild(t, explicitText, "tag").Value != 26 {
		t.Errorf("explicitText schema was not preserved: %#v", explicitText.Children)
	}

	unknown := requirePolicyChild(t, qualifiers, "2")
	raw, ok := requirePolicyChild(t, unknown, "raw").Value.(cryptobyte.String)
	if !ok || !bytes.Equal(raw, unknownRaw) {
		t.Errorf("unknown qualifier raw = %#v, want content bytes %x", raw, unknownRaw)
	}
}

func TestCertificatePoliciesStrictRejectsMalformedQualifiers(t *testing.T) {
	tests := map[string][]byte{
		"duplicate policy identifier": buildCertificatePoliciesWithIdentifiers(
			testDVPolicyOID,
			testDVPolicyOID,
		),
		"empty qualifiers": buildCertificatePolicyFixture(func(*cryptobyte.Builder) {}),
		"CPS wrong tag": buildCertificatePolicyFixture(func(builder *cryptobyte.Builder) {
			addPolicyQualifierFixture(builder, testCPSOID, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.UTF8String, func(builder *cryptobyte.Builder) {
					builder.AddBytes([]byte("https://example.test/cps"))
				})
			})
		}),
		"CPS empty": buildCertificatePolicyFixture(func(builder *cryptobyte.Builder) {
			addPolicyQualifierFixture(builder, testCPSOID, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.IA5String, func(*cryptobyte.Builder) {})
			})
		}),
		"unsupported DisplayText": buildCertificatePolicyFixture(func(builder *cryptobyte.Builder) {
			addPolicyQualifierFixture(builder, testUserNoticeOID, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
					builder.AddASN1(cryptobyte_asn1.PrintableString, func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte("notice"))
					})
				})
			})
		}),
		"trailing UserNotice data": buildCertificatePolicyFixture(func(builder *cryptobyte.Builder) {
			addPolicyQualifierFixture(builder, testUserNoticeOID, func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
					for _, text := range []string{"one", "two"} {
						builder.AddASN1(cryptobyte_asn1.UTF8String, func(builder *cryptobyte.Builder) {
							builder.AddBytes([]byte(text))
						})
					}
				})
			})
		}),
		"unknown qualifier on anyPolicy": buildCertificatePolicyFixtureForOID(
			stdasn1.ObjectIdentifier{2, 5, 29, 32, 0},
			func(builder *cryptobyte.Builder) {
				addPolicyQualifierFixture(builder, testUnknownQualifierOID, func(builder *cryptobyte.Builder) {
					builder.AddASN1NULL()
				})
			},
		),
	}

	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCertPoliciesStrict(der); err == nil {
				t.Fatal("strict parser accepted malformed CertificatePolicies")
			}
			if got := requirePolicyChild(t, ParseCertPolicies(der), "malformed").Value; got != true {
				t.Errorf("compatibility malformed marker = %v, want true", got)
			}
		})
	}
}

func TestCertificatePoliciesCompatibilityMarksEmptySequence(t *testing.T) {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(*cryptobyte.Builder) {})
	parsed := ParseCertPolicies(builder.BytesOrPanic())
	if requirePolicyChild(t, parsed, "malformed").Value != true ||
		requirePolicyChild(t, parsed, "empty").Value != true {
		t.Errorf("empty CertificatePolicies compatibility schema = %#v", parsed.Children)
	}
}

func TestDecodeCertificatePolicyIdentifiersStrict(t *testing.T) {
	der := buildCertificatePolicyFixture(nil)
	parsed, err := ParseCertPoliciesStrict(der)
	if err != nil {
		t.Fatalf("ParseCertPoliciesStrict() error = %v", err)
	}
	if parsed.Children["unprocessed"] != nil {
		t.Fatal("known CertificatePolicies content was marked unprocessed")
	}
	identifiers, err := DecodeCertificatePolicyIdentifiersStrict(der)
	if err != nil {
		t.Fatalf("DecodeCertificatePolicyIdentifiersStrict() error = %v", err)
	}
	if len(identifiers) != 1 || identifiers[0] != oid.CABFDomainValidatedPolicy {
		t.Fatalf("identifiers = %#v, want [%s]", identifiers, oid.CABFDomainValidatedPolicy)
	}
	if _, err := DecodeCertificatePolicyIdentifiersStrict([]byte{0x30, 0x00}); err == nil {
		t.Fatal("empty CertificatePolicies was accepted")
	}
}
