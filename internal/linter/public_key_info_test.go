package linter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/cavoq/PCL/internal/policy"
)

func TestLintSubjectPublicKeyInfo_NilCrypto(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			Crypto: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Crypto is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSubjectPublicKeyInfo_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when SubjectPublicKeyInfo is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSubjectPublicKeyInfo_EmptyAllowedAlgorithms(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when AllowedAlgorithms is empty, got %d", len(job.Result.Findings))
	}
}

func TestLintSubjectPublicKeyInfo_RSA_Allowed(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &rsaKey.PublicKey,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"RSA": {MinSize: 2048},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for allowed RSA key")
	}
}

func TestLintSubjectPublicKeyInfo_RSA_TooSmall(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &rsaKey.PublicKey,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"RSA": {MinSize: 2048},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for RSA key that is too small")
	}
}

func TestLintSubjectPublicKeyInfo_RSA_NotAllowed(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &rsaKey.PublicKey,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {MinSize: 256},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.subject_public_key_info" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for RSA key when only EC is allowed")
	}
}

func TestLintSubjectPublicKeyInfo_EC_Allowed(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &ecKey.PublicKey,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {
							MinSize:       256,
							AllowedCurves: []string{"P-256"},
						},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for allowed EC key")
	}
}

func TestLintSubjectPublicKeyInfo_EC_CurveNotAllowed(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &ecKey.PublicKey,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {
							MinSize:       256,
							AllowedCurves: []string{"P-384", "P-521"},
						},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for EC key with disallowed curve")
	}
}

func TestLintSubjectPublicKeyInfo_EC_TooSmall(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &ecKey.PublicKey,
		},
		Policy: &policy.Policy{
			Crypto: &policy.CryptoRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {
							MinSize:       384,
							AllowedCurves: []string{"P-256", "P-384"},
						},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for EC key that is too small")
	}
}
