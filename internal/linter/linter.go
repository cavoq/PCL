package linter

import (
	"crypto/x509"

	"github.com/cavoq/RCV/internal/policy"
)

type Linter struct {
	Cert   *x509.Certificate
	Policy *policy.Policy
	Result Result
}

func NewLinter(cert *x509.Certificate, pol *policy.Policy) *Linter {
	return &Linter{
		Cert:   cert,
		Policy: pol,
		Result: Result{Cert: cert},
	}
}

func (l *Linter) LintAll() Result {
	l.LintValidity()
	return l.Result
}
