package output

import (
	"slices"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

func TestFromPolicyResults_Empty(t *testing.T) {
	result := FromPolicyResults(nil)

	if result.Meta.TotalCerts != 0 {
		t.Errorf("expected 0 certs, got %d", result.Meta.TotalCerts)
	}
	if result.Meta.TotalRules != 0 {
		t.Errorf("expected 0 rules, got %d", result.Meta.TotalRules)
	}
	if len(result.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(result.Results))
	}
}

func TestFromPolicyResults_CountsVerdicts(t *testing.T) {
	checkedAt := time.Now()
	policyResults := []policy.Result{
		{
			PolicyID:  "test-policy",
			CertType:  "leaf",
			CheckedAt: checkedAt,
			Results: []rule.Result{
				{RuleID: "r1", Verdict: rule.VerdictPass},
				{RuleID: "r2", Verdict: rule.VerdictPass},
				{RuleID: "r3", Verdict: rule.VerdictFail, Severity: "error"},
				{RuleID: "r4", Verdict: rule.VerdictFail, Severity: "warning"},
				{RuleID: "r5", Verdict: rule.VerdictSkip},
			},
		},
	}

	result := FromPolicyResults(policyResults)

	if result.Meta.TotalCerts != 1 {
		t.Errorf("expected 1 cert, got %d", result.Meta.TotalCerts)
	}
	if result.Meta.TotalRules != 5 {
		t.Errorf("expected 5 rules, got %d", result.Meta.TotalRules)
	}
	if result.Meta.PassedRules != 2 {
		t.Errorf("expected 2 passed, got %d", result.Meta.PassedRules)
	}
	if result.Meta.FailedRules != 2 {
		t.Errorf("expected 2 failed, got %d", result.Meta.FailedRules)
	}
	if result.Meta.SkippedRules != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Meta.SkippedRules)
	}
	if result.Meta.CheckedAt != checkedAt {
		t.Errorf("expected CheckedAt %v, got %v", checkedAt, result.Meta.CheckedAt)
	}

	// Check that counts are set on the policy result
	if result.Results[0].Counts.Passed != 2 {
		t.Errorf("expected policy counts passed=2, got %d", result.Results[0].Counts.Passed)
	}
	if result.Results[0].Counts.Warned != 1 {
		t.Errorf("expected policy counts warned=1, got %d", result.Results[0].Counts.Warned)
	}
}

func TestFromPolicyResults_MultiplePolicies(t *testing.T) {
	policyResults := []policy.Result{
		{
			PolicyID: "policy1",
			Results: []rule.Result{
				{RuleID: "r1", Verdict: rule.VerdictPass},
			},
		},
		{
			PolicyID: "policy2",
			Results: []rule.Result{
				{RuleID: "r2", Verdict: rule.VerdictFail},
				{RuleID: "r3", Verdict: rule.VerdictSkip},
			},
		},
	}

	result := FromPolicyResults(policyResults)

	if result.Meta.TotalCerts != 2 {
		t.Errorf("expected 2 certs, got %d", result.Meta.TotalCerts)
	}
	if result.Meta.TotalRules != 3 {
		t.Errorf("expected 3 rules, got %d", result.Meta.TotalRules)
	}
}

func TestFilterRules(t *testing.T) {
	output := LintOutput{
		Results: []policy.Result{
			{
				PolicyID: "test",
				Results: []rule.Result{
					{RuleID: "r1", Verdict: rule.VerdictPass},
					{RuleID: "r2", Verdict: rule.VerdictFail},
					{RuleID: "r3", Verdict: rule.VerdictSkip},
				},
			},
		},
	}

	tests := []struct {
		name string
		opts Options
		want []string
	}{
		{"passed", Options{ShowPassed: true}, []string{"r1"}},
		{"failed", Options{ShowFailed: true}, []string{"r2"}},
		{"skipped", Options{ShowSkipped: true}, []string{"r3"}},
		{"all", Options{ShowPassed: true, ShowFailed: true, ShowSkipped: true}, []string{"r1", "r2", "r3"}},
		{"none", Options{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, result := range FilterRules(output, tt.opts).Results[0].Results {
				got = append(got, result.RuleID)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("filtered rules = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterRules_PreservesMetadata(t *testing.T) {
	checkedAt := time.Now()
	output := LintOutput{
		Meta: LintMeta{
			CheckedAt:    checkedAt,
			TotalCerts:   5,
			TotalRules:   10,
			PassedRules:  7,
			FailedRules:  2,
			SkippedRules: 1,
		},
		Results: []policy.Result{
			{
				PolicyID:  "test",
				CertType:  "leaf",
				CertPath:  "/path/to/cert.pem",
				Verdict:   "pass",
				CheckedAt: checkedAt,
				Counts:    policy.Counts{Passed: 1, Failed: 0},
				Results: []rule.Result{
					{RuleID: "r1", Verdict: rule.VerdictPass},
				},
			},
		},
	}

	opts := Options{ShowPassed: true}
	filtered := FilterRules(output, opts)

	if filtered.Meta.TotalCerts != 5 {
		t.Errorf("meta should be preserved")
	}
	if filtered.Results[0].PolicyID != "test" {
		t.Errorf("policy ID should be preserved")
	}
	if filtered.Results[0].CertPath != "/path/to/cert.pem" {
		t.Errorf("cert path should be preserved")
	}
}
