package linter

import (
	"fmt"
	"time"
)

func (l *Linter) LintValidity() {
	rule := l.Policy.Validity
	if l.Cert.NotBefore.IsZero() || l.Cert.NotAfter.IsZero() {
		return
	}

	validityDays := int(l.Cert.NotAfter.Sub(l.Cert.NotBefore).Hours() / 24)

	if rule != nil {
		if rule.MinExpiryDays != nil && validityDays < *rule.MinExpiryDays {
			l.Result.AddWarning(
				"validity",
				fmt.Sprintf("Validity period %d days < recommended min %d", validityDays, *rule.MinExpiryDays),
				Semantic,
			)
		}
		if rule.MaxExpiryDays != nil && validityDays > *rule.MaxExpiryDays {
			l.Result.AddViolation(
				"validity",
				fmt.Sprintf("Validity period %d days > max allowed %d", validityDays, *rule.MaxExpiryDays),
				Semantic,
			)
		}
	}

	now := time.Now()
	if now.Before(l.Cert.NotBefore) {
		if l.Cert.NotBefore.Sub(now) < 5*time.Minute {
			l.Result.AddWarning(
				"validity.notBefore",
				fmt.Sprintf("Certificate will become valid soon at %s", l.Cert.NotBefore),
				Functional,
			)
		} else {
			l.Result.AddViolation(
				"validity.notBefore",
				fmt.Sprintf("Certificate not yet valid: starts at %s", l.Cert.NotBefore),
				Functional,
			)
		}
	}

	if now.After(l.Cert.NotAfter) {
		l.Result.AddViolation(
			"validity.notAfter",
			fmt.Sprintf("Certificate expired: expired at %s", l.Cert.NotAfter),
			Functional,
		)
	}
}
