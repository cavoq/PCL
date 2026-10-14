package zcrypto

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	ocspAccessMethod      = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01}
	caIssuersAccessMethod = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02}
)

// accessDescription is an AIA entry: the accessMethod OID contents and an
// encoded GeneralName.
type accessDescription struct {
	method   []byte
	location []byte
}

func buildAIA(descriptions ...accessDescription) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, description := range descriptions {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) { b.AddBytes(description.method) })
				b.AddBytes(description.location)
			})
		}
	})
	return b.BytesOrPanic()
}

// buildAIAValue lists the OCSP and CA Issuers URIs that are not empty.
func buildAIAValue(ocspURI, caIssuersURI string) []byte {
	var descriptions []accessDescription
	if ocspURI != "" {
		descriptions = append(descriptions, accessDescription{ocspAccessMethod, generalName(6, []byte(ocspURI))})
	}
	if caIssuersURI != "" {
		descriptions = append(descriptions, accessDescription{caIssuersAccessMethod, generalName(6, []byte(caIssuersURI))})
	}
	return buildAIA(descriptions...)
}

// checkNodeValues fails unless each path resolves below root, to the given
// value when it is not nil.
func checkNodeValues(t *testing.T, root *node.Node, want map[string]any) {
	t.Helper()
	for path, value := range want {
		child, ok := root.Resolve(path)
		if !ok {
			t.Errorf("%s not found", path)
		} else if value != nil && child.Value != value {
			t.Errorf("%s = %v, want %v", path, child.Value, value)
		}
	}
}

func TestParseAIAStrict(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  map[string]any
	}{
		{"valid AIA with HTTP OCSP and CA Issuers", buildAIAValue("http://ocsp.example.com", "http://ca.example.com/cert.der"),
			map[string]any{
				"count":                             2,
				"accessDescriptions.0.accessMethod": "1.3.6.1.5.5.7.48.1",
				"accessDescriptions.0.accessLocation.type":   "uniformResourceIdentifier",
				"accessDescriptions.0.accessLocation.tag":    6,
				"accessDescriptions.0.accessLocation.scheme": "http",
			}},
		{"AIA with DNS name instead of URI",
			buildAIA(accessDescription{ocspAccessMethod, generalName(2, []byte("ocsp.example.com"))}),
			map[string]any{"accessDescriptions.0.accessLocation.type": "dNSName"}},
		{"contains OCSP check", buildAIAValue("http://ocsp.example.com", ""), map[string]any{"containsOCSP": true}},
		{"contains CA Issuers check", buildAIAValue("", "http://ca.example.com"), map[string]any{"containsCaIssuers": true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := ParseAIAStrict(tt.value)
			if err != nil {
				t.Fatalf("ParseAIAStrict() error = %v", err)
			}
			checkNodeValues(t, n, tt.want)
		})
	}
}

func TestParseCRLDPStrict(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  map[string]any
	}{
		{"valid CRL DP with HTTP URI", buildCRLDP("http://crl.example.com/ca.crl", nil, nil), map[string]any{
			"empty":                             false,
			"distributionPoints.0.hasFullName":  true,
			"distributionPoints.0.hasReasons":   false,
			"distributionPoints.0.hasCRLIssuer": false,
			"distributionPoints.0.distributionPoint.fullName.generalNames.0.type":   "uniformResourceIdentifier",
			"distributionPoints.0.distributionPoint.fullName.generalNames.0.scheme": "http",
		}},
		{"CRL DP with reasons field", buildCRLDP("http://crl.example.com", []byte{0x06, 0x40}, nil),
			map[string]any{"distributionPoints.0.hasReasons": true}},
		{"CRL DP with cRLIssuer field", buildCRLDP("http://crl.example.com", nil, generalName(2, []byte("issuer.example"))),
			map[string]any{"distributionPoints.0.hasCRLIssuer": true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := ParseCRLDPStrict(tt.value)
			if err != nil {
				t.Fatalf("ParseCRLDPStrict() error = %v", err)
			}
			checkNodeValues(t, n, tt.want)
		})
	}
}

func TestStrictExtensionParsersRejectMalformedDER(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		parse func([]byte) (*node.Node, error)
	}{
		{
			name:  "AIA",
			value: append(buildAIAValue("http://ocsp.example", ""), 0x00),
			parse: ParseAIAStrict,
		},
		{
			name:  "CRL distribution points",
			value: append(buildCRLDP("http://crl.example", nil, nil), 0x00),
			parse: ParseCRLDPStrict,
		},
		{
			name:  "certificate policies",
			value: append(buildCertPoliciesValue("2.23.140.1.2.1", "", ""), 0x00),
			parse: ParseCertPoliciesStrict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.parse(tt.value); err == nil {
				t.Fatal("strict parser accepted trailing DER")
			}
		})
	}
}
