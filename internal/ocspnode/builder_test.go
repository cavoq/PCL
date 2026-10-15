package ocspnode

import (
	"crypto"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/testpki"
	"golang.org/x/crypto/ocsp"
)

func TestBuildTree(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	sha256WithRSA := "1.2.840.113549.1.1.11"
	tests := []struct {
		name     string
		response ocsp.Response
		// want maps tree paths to their values; nil only requires the path.
		want map[string]any
	}{
		{
			name: "good with SHA-256 RSA",
			response: ocsp.Response{
				Status:       ocsp.Good,
				SerialNumber: big.NewInt(100),
				ThisUpdate:   now,
				NextUpdate:   now.Add(time.Hour),
				IssuerHash:   crypto.SHA256,
			},
			want: map[string]any{
				"ocsp.status":                             "Good",
				"ocsp.serialNumber":                       "100",
				"ocsp.signatureAlgorithm.oid":             sha256WithRSA,
				"ocsp.tbsSignatureAlgorithm.oid":          sha256WithRSA,
				"ocsp.signatureAlgorithm.parameters.null": true,
				"ocsp.issuerHash":                         "SHA256",
			},
		},
		{
			name: "revoked",
			response: ocsp.Response{
				Status:           ocsp.Revoked,
				SerialNumber:     big.NewInt(100),
				ThisUpdate:       now,
				NextUpdate:       now.Add(time.Hour),
				RevokedAt:        now.Add(-30 * time.Minute),
				RevocationReason: ocsp.Superseded,
				IssuerHash:       crypto.SHA256,
			},
			want: map[string]any{
				"ocsp.status":           "Revoked",
				"ocsp.revokedAt":        nil,
				"ocsp.revocationReason": nil,
			},
		},
	}

	validity := testpki.Validity(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	issuer := testpki.Issue(t, "Test Issuer", nil, testpki.CA(), validity)
	responder := testpki.Issue(t, "Test OCSP Responder", issuer, testpki.Serial(2), testpki.OCSPSigning(), validity)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := BuildTree(testpki.OCSPResponse(t, issuer, responder, tt.response))
			if tree == nil {
				t.Fatal("BuildTree returned nil")
			}
			for path, want := range tt.want {
				node, ok := tree.Resolve(path)
				if !ok {
					t.Errorf("%s not found", path)
				} else if want != nil && node.Value != want {
					t.Errorf("%s = %v, want %v", path, node.Value, want)
				}
			}
		})
	}
}
