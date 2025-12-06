package linter

import (
	"crypto/x509"
	"testing"

	"github.com/cavoq/PCL/internal/policy"
)

func TestIsSignatureAlgorithmAllowed(t *testing.T) {
	tests := []struct {
		name     string
		actual   string
		allowed  []string
		expected bool
	}{
		{"exact match", "SHA256-RSA", []string{"SHA256-RSA", "SHA384-RSA"}, true},
		{"no match", "SHA256-RSA", []string{"SHA384-RSA", "SHA512-RSA"}, false},
		{"wildcard", "SHA256-RSA", []string{"*"}, true},
		{"empty allowed list", "SHA256-RSA", []string{}, false},
		{"single match", "ECDSA-SHA256", []string{"ECDSA-SHA256"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSignatureAlgorithmAllowed(tt.actual, tt.allowed)
			if result != tt.expected {
				t.Errorf("isSignatureAlgorithmAllowed(%q, %v) = %v, want %v",
					tt.actual, tt.allowed, result, tt.expected)
			}
		})
	}
}

func TestLintSignatureAlgorithm_NilCrypto(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			Crypto: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Crypto is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSignatureAlgorithm_NilSignatureAlgorithm(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SignatureAlgorithm: nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when SignatureAlgorithm is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSignatureAlgorithm_EmptyAllowedList(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when AllowedAlgorithms is empty, got %d", len(job.Result.Findings))
	}
}

func TestLintSignatureAlgorithm_Allowed(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{"SHA256-RSA", "SHA384-RSA"},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.signature_algorithm" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for allowed signature algorithm")
	}
}

func TestLintSignatureAlgorithm_NotAllowed(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{"SHA384-RSA", "SHA512-RSA"},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.signature_algorithm" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for disallowed signature algorithm")
	}
}

func TestLintSignatureAlgorithm_Wildcard(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{"*"},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.signature_algorithm" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding when wildcard is allowed")
	}
}

func TestLintSignatureAlgorithm_AllAlgorithms(t *testing.T) {
	algorithms := []struct {
		algo       x509.SignatureAlgorithm
		stringName string
	}{
		{x509.SHA256WithRSA, "SHA256-RSA"},
		{x509.SHA384WithRSA, "SHA384-RSA"},
		{x509.SHA512WithRSA, "SHA512-RSA"},
		{x509.SHA256WithRSAPSS, "SHA256-RSAPSS"},
		{x509.SHA384WithRSAPSS, "SHA384-RSAPSS"},
		{x509.SHA512WithRSAPSS, "SHA512-RSAPSS"},
		{x509.ECDSAWithSHA256, "ECDSA-SHA256"},
		{x509.ECDSAWithSHA384, "ECDSA-SHA384"},
		{x509.ECDSAWithSHA512, "ECDSA-SHA512"},
		{x509.PureEd25519, "Ed25519"},
	}

	for _, alg := range algorithms {
		t.Run(alg.stringName, func(t *testing.T) {
			job := &LintJob{
				Cert: &x509.Certificate{
					SignatureAlgorithm: alg.algo,
				},
				Policy: &policy.Policy{
					Crypto: &policy.CryptoRule{
						SignatureAlgorithm: &policy.SignatureAlgorithmRule{
							AllowedAlgorithms: []string{alg.stringName},
						},
					},
				},
				Result: &LintResult{Valid: true},
			}

			LintSignatureAlgorithm(job)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "crypto.signature_algorithm" && f.Status == StatusPass {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected PASS finding for %s algorithm", alg.stringName)
			}
		})
	}
}
