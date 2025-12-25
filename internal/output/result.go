package output

import (
	"time"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

type LintMeta struct {
	CheckedAt    time.Time `json:"checked_at" yaml:"checked_at"`
	TotalCerts   int       `json:"total_certs" yaml:"total_certs"`
	TotalRules   int       `json:"total_rules" yaml:"total_rules"`
	PassedRules  int       `json:"passed_rules" yaml:"passed_rules"`
	FailedRules  int       `json:"failed_rules" yaml:"failed_rules"`
	SkippedRules int       `json:"skipped_rules" yaml:"skipped_rules"`
}

type LintOutput struct {
	Meta    LintMeta        `json:"meta" yaml:"meta"`
	Results []policy.Result `json:"results" yaml:"results"`
}

func FromPolicyResults(policyResults []policy.Result) LintOutput {
	var passed, failed, skipped, totalRules int

	for _, pr := range policyResults {
		for _, rr := range pr.Results {
			totalRules++
			switch rr.Verdict {
			case rule.VerdictPass:
				passed++
			case rule.VerdictFail:
				failed++
			case rule.VerdictSkip:
				skipped++
			}
		}
	}

	checkedAt := time.Now()
	if len(policyResults) > 0 {
		checkedAt = policyResults[0].CheckedAt
	}

	return LintOutput{
		Meta: LintMeta{
			CheckedAt:    checkedAt,
			TotalCerts:   len(policyResults),
			TotalRules:   totalRules,
			PassedRules:  passed,
			FailedRules:  failed,
			SkippedRules: skipped,
		},
		Results: policyResults,
	}
}

func FilterRules(output LintOutput, opts Options) LintOutput {
	filtered := LintOutput{Meta: output.Meta}

	for _, pr := range output.Results {
		filteredResult := policy.Result{
			PolicyID:  pr.PolicyID,
			CertType:  pr.CertType,
			Verdict:   pr.Verdict,
			CheckedAt: pr.CheckedAt,
			Results:   make([]rule.Result, 0),
		}

		for _, rr := range pr.Results {
			include := false
			switch rr.Verdict {
			case rule.VerdictPass:
				include = opts.ShowPassed
			case rule.VerdictFail:
				include = opts.ShowFailed
			case rule.VerdictSkip:
				include = opts.ShowSkipped
			}
			if include {
				filteredResult.Results = append(filteredResult.Results, rr)
			}
		}
		filtered.Results = append(filtered.Results, filteredResult)
	}

	return filtered
}
