package linter

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cavoq/RCV/internal/policy"
	"github.com/cavoq/RCV/internal/utils"
)

type LintJob struct {
	Cert   *x509.Certificate
	Policy *policy.Policy
	Result *LintResult
}

type Linter struct {
	Jobs []*LintJob
}

func (l *Linter) Execute() {
	for _, job := range l.Jobs {
		LintAll(job)
	}
}

func FromCert(certPath string, pol *policy.Policy) (*LintJob, error) {
	cert, err := utils.GetCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	return NewLintJob(cert, pol), nil
}

func NewLintJob(cert *x509.Certificate, pol *policy.Policy) *LintJob {
	hash := sha256.Sum256(cert.Raw)
	return &LintJob{
		Cert:   cert,
		Policy: pol,
		Result: &LintResult{
			CertFile:  fmt.Sprintf("%x", hash),
			Valid:     true,
			CheckedAt: time.Now().UTC(),
		},
	}
}

func LintAll(job *LintJob) {
	LintValidity(job)
	LintNameRules(job)
	LintSignatureAlgorithm(job)
	LintSignatureValidity(job)
	LintSubjectPublicKeyInfo(job)
	LintKeyUsage(job)
	LintExtendedKeyUsage(job)
	LintBasicConstraints(job)
}

func LintSingle(cert *x509.Certificate, pol *policy.Policy) *LintResult {
	job := NewLintJob(cert, pol)
	LintAll(job)
	return job.Result
}
