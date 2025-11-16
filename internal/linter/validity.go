package linter

import (
	"fmt"
	"time"
)

func (l *Linter) LintValidity() {
	cert := l.Cert
	rule := l.Policy.Validity

	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		l.Result.Add("validity.dates", StatusFail, "notBefore/notAfter missing in certificate")
		return
	}

	now := time.Now()
	totalDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	daysLeft := max(int(cert.NotAfter.Sub(now).Hours()/24), 0)

	switch {
	case now.Before(cert.NotBefore):
		l.Result.Add("validity.notBefore", StatusFail, "certificate not yet valid")
	case now.After(cert.NotAfter):
		l.Result.Add("validity.notAfter", StatusFail, fmt.Sprintf("expired %d days ago", -daysLeft))
	default:
		l.Result.Add("validity.current", StatusPass, fmt.Sprintf("valid - %d days left", daysLeft))
	}

	min := 0
	if rule != nil && rule.MinDays != nil {
		min = *rule.MinDays
	}
	msg := fmt.Sprintf("expires in %d days", daysLeft)
	status := StatusPass
	if daysLeft < min {
		status = StatusWarn
	}
	l.Result.Add("validity.min_expiry", status, msg)

	max := 0
	if rule != nil && rule.MaxDays != nil {
		max = *rule.MaxDays
	}
	msg = fmt.Sprintf("validity %d days", totalDays)
	status = StatusPass
	if totalDays > max {
		status = StatusFail
	}
	l.Result.Add("validity.max_validity", status, msg)
}
