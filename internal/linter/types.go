package linter

import (
	"fmt"
	"time"
)

type Finding struct {
	ID      string
	Status  Status
	Message string
}

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusInfo Status = "INFO"
)

type LintRun struct {
	CertPath   string
	PolicyPath string
	StartedAt  time.Time
	Results    []*LintResult
}

func (r *LintRun) Summary() (passed, failed, warnings int) {
	for _, res := range r.Results {
		if res.Valid {
			passed++
		} else {
			failed++
		}
		for _, f := range res.Findings {
			if f.Status == StatusWarn {
				warnings++
			}
		}
	}
	return
}

type LintResult struct {
	FilePath   string
	Hash       string
	PolicyName string
	Findings   []Finding
	Valid      bool
	CheckedAt  time.Time
}

func (r *LintResult) Add(id string, status Status, msg string) {
	r.Findings = append(r.Findings, Finding{
		ID:      id,
		Status:  status,
		Message: msg,
	})
	if status == StatusFail {
		r.Valid = false
	}
}

func (r *LintResult) AddCheck(id string, pass bool, passMsg, failMsg string) {
	if pass {
		r.Add(id, StatusPass, passMsg)
	} else {
		r.Add(id, StatusFail, failMsg)
	}
}

func (r *LintResult) AddRequirementCheck(id string, missing, present []string, requirement string) {
	if len(missing) == 0 {
		r.Add(id, StatusPass, fmt.Sprintf("required %s present: %v", requirement, present))
	} else {
		r.Add(id, StatusFail, fmt.Sprintf("missing required %s: %v", requirement, missing))
	}
}
