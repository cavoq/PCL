package linter

import (
	"fmt"
	"strings"

	"github.com/cavoq/RCV/internal/policy"
	"github.com/cavoq/RCV/internal/utils"
)

func (l *Linter) LintNameRules() {
	cert := l.Cert
	if l.Policy == nil {
		return
	}

	if l.Policy.Issuer != nil {
		issuerNames := utils.GetIssuerNames(cert)
		l.LintNames(l.Policy.Issuer, issuerNames, "issuer")
	}

	if l.Policy.Subject != nil {
		subjectNames := utils.GetSubjectNames(cert)
		l.LintNames(l.Policy.Subject, subjectNames, "subject")
	}
}

func (l *Linter) LintNames(rule *policy.NameRule, names []string, field string) {
	if rule == nil {
		return
	}

	// 1) wildcard check (NoWildcards)
	if rule.NoWildcards {
		wildcardFound := false
		for _, name := range names {
			if strings.Contains(name, "*") || strings.Contains(name, "?") {
				wildcardFound = true
				break
			}
		}

		status := StatusPass
		msg := "no wildcards found"
		if wildcardFound {
			status = StatusFail
			msg = "wildcards are forbidden but found in name(s)"
		}

		l.Result.Add(fmt.Sprintf("%s.no_wildcards", field), status, msg)
	}
}
