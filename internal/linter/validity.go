package linter

import (
	"fmt"
	"time"
)

func (l *Linter) LintValidity() {
	rule := l.Policy.Validity
	cert := l.Cert
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		return
	}

	now := time.Now()
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	if rule != nil {
		if rule.MinExpiryDays != nil && validityDays < *rule.MinExpiryDays {
			l.Result.AddWarning(
				"validity.notAfter",
				fmt.Sprintf(
					"Certificate will expire in %d days, recommended minimum validity is %d days",
					daysLeft,
					*rule.MinExpiryDays,
				),
			)
		}

		if rule.MaxExpiryDays != nil && validityDays > *rule.MaxExpiryDays {
			l.Result.AddViolation(
				"validity",
				fmt.Sprintf(
					"Certificate validity period is %d days, exceeds maximum allowed %d days",
					validityDays,
					*rule.MaxExpiryDays,
				),
			)
		}
	}

	if now.Before(cert.NotBefore) {
		if cert.NotBefore.Sub(now) < 5*time.Minute {
			l.Result.AddWarning(
				"validity.notBefore",
				fmt.Sprintf("Certificate will become valid soon at %s", cert.NotBefore),
			)
		} else {
			l.Result.AddViolation(
				"validity.notBefore",
				fmt.Sprintf("Certificate not yet valid: starts at %s", cert.NotBefore),
			)
		}
	}

	if now.After(cert.NotAfter) {
		l.Result.AddViolation(
			"validity.notAfter",
			fmt.Sprintf("Certificate expired: expired at %s", cert.NotAfter),
		)
	}
}
