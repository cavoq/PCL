package linter

import (
	"fmt"
	"slices"
)

func (l *Linter) LintSignatureAlgorithm() {
	cert := l.Cert
	rule := l.Policy.Crypto

	if rule == nil ||
		rule.SignatureAlgorithm == nil ||
		len(rule.SignatureAlgorithm.AllowedAlgorithms) == 0 {
		return
	}

	actual := cert.SignatureAlgorithm.String()
	allowed := rule.SignatureAlgorithm.AllowedAlgorithms

	isAllowed := slices.Contains(allowed, "*") || slices.Contains(allowed, actual)

	if isAllowed {
		l.Result.Add(
			"crypto.signature_algorithm",
			StatusPass,
			fmt.Sprintf("signature algorithm allowed - %s", actual),
		)
	} else {
		l.Result.Add(
			"crypto.signature_algorithm",
			StatusFail,
			fmt.Sprintf("signature algorithm not allowed - %s", actual),
		)
	}
}
