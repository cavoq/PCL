package linter

import (
	"crypto/x509"
	"time"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/utils"
)

type LintJob struct {
	Cert   *x509.Certificate
	Chain  []*x509.Certificate
	Policy *policy.Policy
	Result *LintResult
}

type Linter struct {
	Jobs []*LintJob
	Run  *LintRun
}

func (l *Linter) CreateJobs(certs []*utils.CertInfo, policyChain *policy.PolicyChain, certPath, policyPath string) {
	l.Run = &LintRun{
		CertPath:   certPath,
		PolicyPath: policyPath,
		StartedAt:  time.Now().UTC(),
	}

	chain := make([]*x509.Certificate, len(certs))
	for i, c := range certs {
		chain[i] = c.Cert
	}

	for i, certInfo := range certs {
		var pol *policy.Policy
		if i < len(policyChain.Policies) {
			pol = policyChain.Policies[i]
		} else {
			pol = policyChain.Policies[len(policyChain.Policies)-1]
		}

		job := NewLintJob(certInfo, chain, pol)
		l.Jobs = append(l.Jobs, job)
		l.Run.Results = append(l.Run.Results, job.Result)
	}
}

func (l *Linter) Execute() {
	for _, job := range l.Jobs {
		LintAll(job)
	}
}

func NewLintJob(certInfo *utils.CertInfo, chain []*x509.Certificate, pol *policy.Policy) *LintJob {
	policyName := ""
	if pol != nil {
		policyName = pol.Name
	}

	return &LintJob{
		Cert:   certInfo.Cert,
		Chain:  chain,
		Policy: pol,
		Result: &LintResult{
			FilePath:   certInfo.FilePath,
			Hash:       certInfo.Hash,
			PolicyName: policyName,
			Valid:      true,
			CheckedAt:  time.Now().UTC(),
		},
	}
}

func LintAll(job *LintJob) {
	LintBasicFields(job)
	LintValidity(job)
	LintNameRules(job)
	LintSignatureAlgorithm(job)
	LintSignatureValidity(job)
	LintSubjectPublicKeyInfo(job)
	LintKeyUsage(job)
	LintExtendedKeyUsage(job)
	LintBasicConstraints(job)
}
