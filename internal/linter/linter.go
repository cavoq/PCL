package linter

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cavoq/RCV/internal/policy"
)

type Linter struct {
	Cert   *x509.Certificate
	Policy *policy.Policy
	Result *Result
}

func NewLinter(cert *x509.Certificate, pol *policy.Policy) *Linter {
	hash := sha256.Sum256(cert.Raw)
	return &Linter{
		Cert:   cert,
		Policy: pol,
		Result: &Result{
			CertFile:  fmt.Sprintf("%x", hash),
			Valid:     true,
			CheckedAt: time.Now().UTC(),
		},
	}
}

func (l *Linter) LintAll() *Result {
	l.LintValidity()
	l.LintNameRules()
	l.LintSignatureAlgorithm()
	l.LintSignatureValidity()
	l.LintSubjectPublicKeyInfo()
	l.LintKeyUsage()
	return l.Result
}
