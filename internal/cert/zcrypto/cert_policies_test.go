package zcrypto

import (
	stdasn1 "encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Helper to build Certificate Policies extension value
func buildCertPoliciesValue(policyOID string, cpsURI string, explicitText string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// PolicyInformation
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// policyIdentifier
			if policyOID == "2.23.140.1.2.1" { // DV OID
				b.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 23, 140, 1, 2, 1})
			} else {
				b.AddASN1ObjectIdentifier(stdasn1.ObjectIdentifier{2, 5, 29, 32, 0})
			}
			// policyQualifiers (optional)
			if cpsURI != "" || explicitText != "" {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					if cpsURI != "" {
						// PolicyQualifierInfo for CPS
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							// policyQualifierId: id-qt-cps (1.3.6.1.5.5.7.2.1)
							b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
								b.AddBytes([]byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01})
							})
							// qualifier: IA5String
							b.AddASN1(cryptobyte_asn1.IA5String, func(b *cryptobyte.Builder) {
								b.AddBytes([]byte(cpsURI))
							})
						})
					}
					if explicitText != "" {
						// PolicyQualifierInfo for UserNotice
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							// policyQualifierId: id-qt-unotice (1.3.6.1.5.5.7.2.2)
							b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
								b.AddBytes([]byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02})
							})
							// qualifier: UserNotice SEQUENCE
							b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
								// explicitText (UTF8String, tag 12)
								b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
									b.AddBytes([]byte(explicitText))
								})
							})
						})
					}
				})
			}
		})
	})
	return b.BytesOrPanic()
}

func TestParseCertPolicies(t *testing.T) {
	const policy, cps = "2.23.140.1.2.1", "http://cps.example.com/policy"
	tests := []struct {
		name  string
		value []byte
		want  map[string]any
	}{
		{"policy with CPS URI", buildCertPoliciesValue(policy, cps, ""),
			map[string]any{"policyInformations.0.policyQualifiers.1.3.6.1.5.5.7.2.1": nil}},
		{"policy with userNotice explicitText", buildCertPoliciesValue(policy, "", "This is a test notice"),
			map[string]any{"policyInformations.0.policyQualifiers.1.3.6.1.5.5.7.2.2": nil}},
		{"CPS URI encoding is ia5String", buildCertPoliciesValue(policy, cps, ""),
			map[string]any{"policyInformations.0.policyQualifiers.0.encoding": "ia5String"}},
		{"userNotice explicitText encoding", buildCertPoliciesValue(policy, "", "Test notice"),
			map[string]any{"policyInformations.0.policyQualifiers.0.userNotice.explicitText.encoding": "utf8String"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := ParseCertPolicies(tt.value)
			if n == nil {
				t.Fatalf("ParseCertPolicies returned nil")
			}
			checkNodeValues(t, n, tt.want)
		})
	}

	both := ParseCertPolicies(buildCertPoliciesValue(policy, cps, "Test notice"))
	if informations, ok := both.Resolve("policyInformations"); !ok || len(informations.Children) != 1 || informations.Children["0"] == nil {
		t.Fatal("a policy with CPS and userNotice qualifiers must be one policyInformation")
	}
}
