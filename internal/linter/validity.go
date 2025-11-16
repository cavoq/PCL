package linter

import (
	"fmt"
	"math"
	"time"
)

func daysCeil(d time.Duration) int {
	h := d.Hours()
	return int(math.Ceil(h / 24.0))
}

func (l *Linter) LintValidity() {
	cert := l.Cert
	rule := l.Policy.Validity

	if rule == nil {
		return
	}

	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		l.Result.Add("validity.dates", StatusFail, "notBefore/notAfter missing in certificate")
		return
	}

	now := time.Now().UTC()
	notBefore := cert.NotBefore.UTC()
	notAfter := cert.NotAfter.UTC()

	if now.Before(notBefore) {
		l.Result.Add("validity.notBefore", StatusFail, "certificate not yet valid")
	} else if now.After(notAfter) {
		daysSince := daysCeil(now.Sub(notAfter))
		l.Result.Add("validity.notAfter", StatusFail, fmt.Sprintf("certificate expired %d days ago", daysSince))
	} else {
		daysLeft := daysCeil(notAfter.Sub(now))
		l.Result.Add("validity", StatusPass, fmt.Sprintf("certificate valid - %d days left", daysLeft))
	}

	if rule.MinDays != nil {
		l.LintMinValidity(*rule.MinDays, now, notAfter)
	}

	if rule.MaxDays != nil {
		l.LintMaxValidity(*rule.MaxDays, notBefore, notAfter)
	}
}

func (l *Linter) LintMinValidity(minDays int, now, notAfter time.Time) {
	field := "validity.min_validity"

	if now.After(notAfter) {
		l.Result.Add(field, StatusFail, fmt.Sprintf("certificate expired; remaining days < %d", minDays))
		return
	}

	daysLeft := daysCeil(notAfter.Sub(now))

	msg := fmt.Sprintf("(%d days remaining >= %d days required)", daysLeft, minDays)
	status := StatusPass
	if daysLeft < minDays {
		status = StatusWarn
	}
	l.Result.Add(field, status, msg)
}

func (l *Linter) LintMaxValidity(maxDays int, notBefore, notAfter time.Time) {
	field := "validity.max_validity"

	if notAfter.Before(notBefore) {
		l.Result.Add(field, StatusFail, "notAfter is before notBefore (invalid validity period)")
		return
	}

	totalDays := daysCeil(notAfter.Sub(notBefore))
	msg := fmt.Sprintf("(%d days <= %d days maximum)", totalDays, maxDays)
	status := StatusPass
	if totalDays > maxDays {
		status = StatusFail
	}
	l.Result.Add(field, status, msg)
}
