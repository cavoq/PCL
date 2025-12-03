package linter

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cavoq/RCV/internal/policy"
)

type LintJob struct {
	Cert   *x509.Certificate
	Policy *policy.Policy
	Result *LintResult
}

type Linter struct {
	Jobs []*LintJob
}

func (l *Linter) CreateJobs(certs []*x509.Certificate, chain *policy.PolicyChain) {
	var jobs []*LintJob

	for i, cert := range certs {
		var pol *policy.Policy
		if i < len(chain.Policies) {
			pol = chain.Policies[i]
		} else {
			pol = chain.Policies[len(chain.Policies)-1]
		}

		job := NewLintJob(cert, pol)
		jobs = append(jobs, job)
	}

	l.Jobs = jobs
}

func (l *Linter) Execute() {
	for _, job := range l.Jobs {
		LintAll(job)
	}
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
