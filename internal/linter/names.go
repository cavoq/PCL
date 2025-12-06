package linter

import (
	"fmt"
	"strings"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/utils"
)

func LintNameRules(job *LintJob) {
	cert := job.Cert
	if job.Policy == nil {
		return
	}

	if job.Policy.Issuer != nil {
		issuerNames := utils.GetIssuerNames(cert)
		LintNoWildcards(job, job.Policy.Issuer, issuerNames, "issuer")
	}

	if job.Policy.Subject != nil {
		subjectNames := utils.GetSubjectNames(cert)
		LintNoWildcards(job, job.Policy.Subject, subjectNames, "subject")
	}
}

func LintNoWildcards(job *LintJob, rule *policy.NameRule, names []string, field string) {
	if rule == nil {
		return
	}

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

		job.Result.Add(fmt.Sprintf("%s.no_wildcards", field), status, msg)
	}
}
