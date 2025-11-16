package linter

import "time"

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

type Result struct {
	CertFile  string
	Findings  []Finding
	Valid     bool
	CheckedAt time.Time
}

func (r *Result) Add(id string, status Status, msg string) {
	r.Findings = append(r.Findings, Finding{
		ID:      id,
		Status:  status,
		Message: msg,
	})
	if status == StatusFail {
		r.Valid = false
	}
}
