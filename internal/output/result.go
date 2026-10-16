// Package output provides lint result formatting and output.
package output

import (
	"time"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

type LintMeta struct {
	CheckedAt time.Time `json:"checked_at" yaml:"checked_at"`
	// ValidationTime is the time the run evaluated certificate, CRL and OCSP
	// currency and path validity at; zero when the caller did not record it.
	ValidationTime time.Time `json:"validation_time,omitzero" yaml:"validation_time,omitempty"`
	// Policies identifies each evaluated policy pack and the source it
	// implements.
	Policies []PolicyInfo `json:"policies,omitempty" yaml:"policies,omitempty"`
	// Chain is the certificate chain the certificate results belong to.
	Chain        *Chain `json:"chain,omitempty" yaml:"chain,omitempty"`
	TotalCerts   int    `json:"total_certs" yaml:"total_certs"`
	TotalRules   int    `json:"total_rules" yaml:"total_rules"`
	PassedRules  int    `json:"passed_rules" yaml:"passed_rules"`
	FailedRules  int    `json:"failed_rules" yaml:"failed_rules"`
	SkippedRules int    `json:"skipped_rules" yaml:"skipped_rules"`
}

// PolicyInfo identifies an evaluated policy pack by its id and version and
// the standard and edition its metadata names.
type PolicyInfo struct {
	ID       string `json:"id" yaml:"id"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Title    string `json:"title,omitempty" yaml:"title,omitempty"`
	Standard string `json:"standard,omitempty" yaml:"standard,omitempty"`
	Edition  string `json:"edition,omitempty" yaml:"edition,omitempty"`
	Source   string `json:"source,omitempty" yaml:"source,omitempty"`
}

// NewPolicyInfo identifies p.
func NewPolicyInfo(p policy.Policy) PolicyInfo {
	info := PolicyInfo{ID: p.ID, Version: p.Version}
	if p.Metadata != nil {
		info.Title = p.Metadata.Title
		info.Standard = p.Metadata.Standard
		info.Edition = p.Metadata.Edition
		info.Source = p.Metadata.Source
	}
	return info
}

// Chain is the evaluated certificate chain, target first.
type Chain struct {
	// PathValidated reports that the chain was validated as an RFC 5280
	// certification path, which requires explicit trust anchors.
	PathValidated bool `json:"path_validated" yaml:"path_validated"`
	// Anchored reports that the validated path reached a trust anchor.
	Anchored bool `json:"anchored" yaml:"anchored"`
	// Alternative reports that the constructed path failed validation and a
	// valid alternative path was evaluated instead.
	Alternative  bool               `json:"alternative" yaml:"alternative"`
	Certificates []ChainCertificate `json:"certificates" yaml:"certificates"`
}

// ChainCertificate identifies one certificate of the evaluated chain.
type ChainCertificate struct {
	CertType    string `json:"cert_type" yaml:"cert_type"`
	Subject     string `json:"subject" yaml:"subject"`
	Issuer      string `json:"issuer" yaml:"issuer"`
	Serial      string `json:"serial" yaml:"serial"`
	SHA256      string `json:"sha256" yaml:"sha256"`
	CertPath    string `json:"cert_path,omitempty" yaml:"cert_path,omitempty"`
	TrustAnchor bool   `json:"trust_anchor" yaml:"trust_anchor"`
}

type LintOutput struct {
	Meta    LintMeta        `json:"meta" yaml:"meta"`
	Results []policy.Result `json:"results" yaml:"results"`
}

// FromPolicyResults summarizes policyResults. The results are kept
// unfiltered; formatters apply the visibility options when rendering.
func FromPolicyResults(policyResults []policy.Result) LintOutput {
	var total ruleCounts
	totalRules := 0
	for _, pr := range policyResults {
		total = total.add(countRules(pr.Results))
		totalRules += len(pr.Results)
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
			PassedRules:  total.passed,
			FailedRules:  total.failed,
			SkippedRules: total.skipped,
		},
		Results: policyResults,
	}
}

// ruleCounts counts rule verdicts; warned counts the failed rules of
// warning severity.
type ruleCounts struct {
	passed, failed, skipped, warned int
}

func countRules(results []rule.Result) ruleCounts {
	var counts ruleCounts
	for _, rr := range results {
		switch rr.Verdict {
		case rule.VerdictPass:
			counts.passed++
		case rule.VerdictFail:
			counts.failed++
			if rr.Severity == rule.SeverityWarning {
				counts.warned++
			}
		case rule.VerdictSkip:
			counts.skipped++
		}
	}
	return counts
}

func (counts ruleCounts) add(other ruleCounts) ruleCounts {
	return ruleCounts{
		passed:  counts.passed + other.passed,
		failed:  counts.failed + other.failed,
		skipped: counts.skipped + other.skipped,
		warned:  counts.warned + other.warned,
	}
}

// filterRules keeps the rule results opts shows, leaving the metadata and
// policy results otherwise unchanged.
func filterRules(output LintOutput, opts Options) LintOutput {
	filtered := LintOutput{Meta: output.Meta, Results: make([]policy.Result, 0, len(output.Results))}
	for _, pr := range output.Results {
		pr.Results = visibleRules(pr.Results, opts)
		filtered.Results = append(filtered.Results, pr)
	}
	return filtered
}

func visibleRules(results []rule.Result, opts Options) []rule.Result {
	visible := make([]rule.Result, 0, len(results))
	for _, rr := range results {
		switch {
		case rr.Verdict == rule.VerdictPass && opts.ShowPassed,
			rr.Verdict == rule.VerdictFail && opts.ShowFailed,
			rr.Verdict == rule.VerdictSkip && opts.ShowSkipped:
			visible = append(visible, rr)
		}
	}
	return visible
}
