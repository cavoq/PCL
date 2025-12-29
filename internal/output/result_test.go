package output

import (
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

func TestFilterRules_ShowPassed(t *testing.T) {
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

	opts := Options{ShowPassed: true, ShowFailed: false, ShowSkipped: false}
	filtered := FilterRules(output, opts)

	if len(filtered.Results[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(filtered.Results[0].Results))
	}
	if filtered.Results[0].Results[0].Verdict != rule.VerdictPass {
		t.Errorf("expected pass verdict, got %s", filtered.Results[0].Results[0].Verdict)
	}
}

func TestFilterRules_ShowFailed(t *testing.T) {
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

	opts := Options{ShowPassed: false, ShowFailed: true, ShowSkipped: false}
	filtered := FilterRules(output, opts)

	if len(filtered.Results[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(filtered.Results[0].Results))
	}
	if filtered.Results[0].Results[0].Verdict != rule.VerdictFail {
		t.Errorf("expected fail verdict, got %s", filtered.Results[0].Results[0].Verdict)
	}
}

func TestFilterRules_ShowSkipped(t *testing.T) {
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

	opts := Options{ShowPassed: false, ShowFailed: false, ShowSkipped: true}
	filtered := FilterRules(output, opts)

	if len(filtered.Results[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(filtered.Results[0].Results))
	}
	if filtered.Results[0].Results[0].Verdict != rule.VerdictSkip {
		t.Errorf("expected skip verdict, got %s", filtered.Results[0].Results[0].Verdict)
	}
}

func TestFilterRules_ShowAll(t *testing.T) {
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

	opts := Options{ShowPassed: true, ShowFailed: true, ShowSkipped: true}
	filtered := FilterRules(output, opts)

	if len(filtered.Results[0].Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(filtered.Results[0].Results))
	}
}

func TestFilterRules_ShowNone(t *testing.T) {
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

	opts := Options{ShowPassed: false, ShowFailed: false, ShowSkipped: false}
	filtered := FilterRules(output, opts)

	if len(filtered.Results[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(filtered.Results[0].Results))
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
