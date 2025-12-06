package linter

import (
	"fmt"
	"time"
)

func LintValidity(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Validity

	if rule == nil {
		return
	}

	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		job.Result.Add("validity.dates", StatusFail, "notBefore/notAfter missing in certificate")
		return
	}

	now := time.Now().UTC()
	notBefore := cert.NotBefore.UTC()
	notAfter := cert.NotAfter.UTC()

	if now.Before(notBefore) {
		job.Result.Add("validity.notBefore", StatusFail, "certificate not yet valid")
	} else if now.After(notAfter) {
		daysSince := daysCeil(now.Sub(notAfter))
		job.Result.Add("validity.notAfter", StatusFail, fmt.Sprintf("certificate expired %d days ago", daysSince))
	} else {
		daysLeft := daysCeil(notAfter.Sub(now))
		job.Result.Add("validity", StatusPass, fmt.Sprintf("certificate valid - %d days left", daysLeft))
	}

	if rule.MinDays != nil {
		LintMinValidity(job, *rule.MinDays, now, notAfter)
	}

	if rule.MaxDays != nil {
		LintMaxValidity(job, *rule.MaxDays, notBefore, notAfter)
	}
}

func LintMinValidity(job *LintJob, minDays int, now, notAfter time.Time) {
	field := "validity.min_validity"

	if now.After(notAfter) {
		job.Result.Add(field, StatusFail, fmt.Sprintf("certificate expired; remaining days < %d", minDays))
		return
	}

	daysLeft := daysCeil(notAfter.Sub(now))
	msg := fmt.Sprintf("(%d days remaining >= %d days required)", daysLeft, minDays)

	status := StatusPass
	if daysLeft < minDays {
		status = StatusWarn
	}

	job.Result.Add(field, status, msg)
}

func LintMaxValidity(job *LintJob, maxDays int, notBefore, notAfter time.Time) {
	field := "validity.max_validity"

	if notAfter.Before(notBefore) {
		job.Result.Add(field, StatusFail, "notAfter is before notBefore (invalid validity period)")
		return
	}

	totalDays := daysCeil(notAfter.Sub(notBefore))
	msg := fmt.Sprintf("(%d days <= %d days maximum)", totalDays, maxDays)

	status := StatusPass
	if totalDays > maxDays {
		status = StatusFail
	}

	job.Result.Add(field, status, msg)
}

func daysCeil(d time.Duration) int {
	days := d.Hours() / 24
	if days == float64(int(days)) {
		return int(days)
	}
	return int(days) + 1
}
