package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/cavoq/PCL/internal/policy"
)

func TestLintNameRules_NilPolicy(t *testing.T) {
	job := &LintJob{
		Cert:   &x509.Certificate{},
		Policy: nil,
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Policy is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintNameRules_NilSubjectAndIssuer(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			Subject: nil,
			Issuer:  nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Subject and Issuer are nil, got %d", len(job.Result.Findings))
	}
}

func TestLintNoWildcards_NilRule(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	LintNoWildcards(job, nil, []string{"test.example.com"}, "subject")

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when rule is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintNoWildcards_NoWildcardsDisabled(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: false,
	}

	LintNoWildcards(job, rule, []string{"*.example.com"}, "subject")

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when NoWildcards is false, got %d", len(job.Result.Findings))
	}
}

func TestLintNoWildcards_NoWildcardsFound(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"test.example.com", "www.example.com"}, "subject")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding when no wildcards found")
	}
}

func TestLintNoWildcards_WildcardStar(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"*.example.com"}, "subject")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding when * wildcard found")
	}
}

func TestLintNoWildcards_WildcardQuestion(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"test?.example.com"}, "subject")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding when ? wildcard found")
	}
}

func TestLintNoWildcards_IssuerField(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"*.example.com"}, "issuer")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "issuer.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding with issuer prefix")
	}
}

func TestLintNameRules_SubjectWithWildcard(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "*.example.com",
			},
		},
		Policy: &policy.Policy{
			Subject: &policy.NameRule{
				NoWildcards: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for subject with wildcard")
	}
}

func TestLintNameRules_IssuerWithWildcard(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "*.issuer.com",
			},
		},
		Policy: &policy.Policy{
			Issuer: &policy.NameRule{
				NoWildcards: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "issuer.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for issuer with wildcard")
	}
}

func TestLintNameRules_EmptyNames(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Subject: pkix.Name{},
		},
		Policy: &policy.Policy{
			Subject: &policy.NameRule{
				NoWildcards: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for empty subject names")
	}
}
