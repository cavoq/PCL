package linter

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/policy"
)

func TestDaysCeil(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected int
	}{
		{"exactly 1 day", 24 * time.Hour, 1},
		{"exactly 2 days", 48 * time.Hour, 2},
		{"1 day and 1 hour", 25 * time.Hour, 2},
		{"23 hours", 23 * time.Hour, 1},
		{"1 hour", 1 * time.Hour, 1},
		{"0 hours", 0, 0},
		{"exactly 365 days", 365 * 24 * time.Hour, 365},
		{"365 days and 1 minute", 365*24*time.Hour + time.Minute, 366},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := daysCeil(tt.duration)
			if result != tt.expected {
				t.Errorf("daysCeil(%v) = %d, want %d", tt.duration, result, tt.expected)
			}
		})
	}
}

func TestLintValidity_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: time.Now().Add(-24 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		},
		Policy: &policy.Policy{
			Validity: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when rule is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintValidity_ValidCertificate(t *testing.T) {
	now := time.Now().UTC()
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: now.Add(-24 * time.Hour),
			NotAfter:  now.Add(30 * 24 * time.Hour),
		},
		Policy: &policy.Policy{
			Validity: &policy.ValidityRule{},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "validity" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for valid certificate")
	}
}

func TestLintValidity_ExpiredCertificate(t *testing.T) {
	now := time.Now().UTC()
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: now.Add(-60 * 24 * time.Hour),
			NotAfter:  now.Add(-30 * 24 * time.Hour),
		},
		Policy: &policy.Policy{
			Validity: &policy.ValidityRule{},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "validity.notAfter" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for expired certificate")
	}
}

func TestLintValidity_NotYetValid(t *testing.T) {
	now := time.Now().UTC()
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: now.Add(24 * time.Hour),
			NotAfter:  now.Add(60 * 24 * time.Hour),
		},
		Policy: &policy.Policy{
			Validity: &policy.ValidityRule{},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "validity.notBefore" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for not-yet-valid certificate")
	}
}

func TestLintValidity_MissingDates(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			Validity: &policy.ValidityRule{},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "validity.dates" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for missing dates")
	}
}

func TestLintMinValidity(t *testing.T) {
	now := time.Now().UTC()
	minDays := 30

	tests := []struct {
		name           string
		notAfter       time.Time
		expectedStatus Status
	}{
		{"enough days remaining", now.Add(60 * 24 * time.Hour), StatusPass},
		{"not enough days remaining", now.Add(10 * 24 * time.Hour), StatusWarn},
		{"expired", now.Add(-1 * 24 * time.Hour), StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Result: &LintResult{Valid: true},
			}

			LintMinValidity(job, minDays, now, tt.notAfter)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "validity.min_validity" && f.Status == tt.expectedStatus {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for min validity check", tt.expectedStatus)
			}
		})
	}
}

func TestLintMaxValidity(t *testing.T) {
	now := time.Now().UTC()
	maxDays := 365

	tests := []struct {
		name           string
		notBefore      time.Time
		notAfter       time.Time
		expectedStatus Status
	}{
		{"within max", now, now.Add(100 * 24 * time.Hour), StatusPass},
		{"exactly max", now, now.Add(365 * 24 * time.Hour), StatusPass},
		{"exceeds max", now, now.Add(400 * 24 * time.Hour), StatusFail},
		{"invalid period", now.Add(24 * time.Hour), now, StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Result: &LintResult{Valid: true},
			}

			LintMaxValidity(job, maxDays, tt.notBefore, tt.notAfter)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "validity.max_validity" {
					if f.Status == tt.expectedStatus {
						found = true
					}
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for max validity check", tt.expectedStatus)
			}
		})
	}
}
