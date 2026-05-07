package zcrypto

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
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
			b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
				// Parse OID string to bytes (simplified for testing)
				if policyOID == "2.23.140.1.2.1" { // DV OID
					b.AddBytes([]byte{0x60, 0x86, 0x48, 0x01, 0x86, 0xFD, 0x6C, 0x01, 0x02, 0x01})
				} else {
					b.AddBytes([]byte{0x55, 0x1D, 0x20, 0x00}) // anyPolicy
				}
			})
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
	tests := []struct {
		name      string
		extValue  []byte
		checkFunc func(n *node.Node) bool
		expected  bool
	}{
		{
			name:     "policy with CPS URI",
			extValue: buildCertPoliciesValue("2.23.140.1.2.1", "http://cps.example.com/policy", ""),
			checkFunc: func(n *node.Node) bool {
				pi, ok := n.Children["policyInformations"]
				if !ok {
					return false
				}
				p0, ok := pi.Children["0"]
				if !ok {
					return false
				}
				pq, ok := p0.Children["policyQualifiers"]
				if !ok {
					return false
				}
				// Check CPS qualifier exists
				cps, ok := pq.Children["1.3.6.1.5.5.7.2.1"]
				return ok && cps != nil
			},
			expected: true,
		},
		{
			name:     "policy with userNotice explicitText",
			extValue: buildCertPoliciesValue("2.23.140.1.2.1", "", "This is a test notice"),
			checkFunc: func(n *node.Node) bool {
				pi, ok := n.Children["policyInformations"]
				if !ok {
					return false
				}
				p0, ok := pi.Children["0"]
				if !ok {
					return false
				}
				pq, ok := p0.Children["policyQualifiers"]
				if !ok {
					return false
				}
				// Check userNotice qualifier exists
				un, ok := pq.Children["1.3.6.1.5.5.7.2.2"]
				return ok && un != nil
			},
			expected: true,
		},
		{
			name:     "policy with both CPS and userNotice",
			extValue: buildCertPoliciesValue("2.23.140.1.2.1", "http://cps.example.com/policy", "Test notice"),
			checkFunc: func(n *node.Node) bool {
				pi, ok := n.Children["policyInformations"]
				if !ok {
					return false
				}
				// Check that there's exactly 1 policyInformation
				return len(pi.Children) == 1 && pi.Children["0"] != nil
			},
			expected: true,
		},
		{
			name:     "CPS URI encoding is ia5String",
			extValue: buildCertPoliciesValue("2.23.140.1.2.1", "http://cps.example.com/policy", ""),
			checkFunc: func(n *node.Node) bool {
				pi, ok := n.Children["policyInformations"]
				if !ok {
					return false
				}
				p0, ok := pi.Children["0"]
				if !ok {
					return false
				}
				pq, ok := p0.Children["policyQualifiers"]
				if !ok {
					return false
				}
				q0, ok := pq.Children["0"]
				if !ok {
					return false
				}
				encoding, ok := q0.Children["encoding"]
				if !ok {
					return false
				}
				s, ok := encoding.Value.(string)
				return ok && s == "ia5String"
			},
			expected: true,
		},
		{
			name:     "userNotice explicitText encoding",
			extValue: buildCertPoliciesValue("2.23.140.1.2.1", "", "Test notice"),
			checkFunc: func(n *node.Node) bool {
				pi, ok := n.Children["policyInformations"]
				if !ok {
					return false
				}
				p0, ok := pi.Children["0"]
				if !ok {
					return false
				}
				pq, ok := p0.Children["policyQualifiers"]
				if !ok {
					return false
				}
				q0, ok := pq.Children["0"]
				if !ok {
					return false
				}
				un, ok := q0.Children["userNotice"]
				if !ok {
					return false
				}
				et, ok := un.Children["explicitText"]
				if !ok {
					return false
				}
				encoding, ok := et.Children["encoding"]
				if !ok {
					return false
				}
				s, ok := encoding.Value.(string)
				return ok && s == "utf8String"
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := ParseCertPolicies(tt.extValue)
			if n == nil {
				t.Fatalf("ParseCertPolicies returned nil")
			}
			got := tt.checkFunc(n)
			if got != tt.expected {
				t.Errorf("check failed: got %v, want %v", got, tt.expected)
			}
		})
	}
}