package linter

import "crypto/x509"

type IssueType string

const (
	Violation IssueType = "violation"
	Warning   IssueType = "warning"
)

type Issue struct {
	Type    IssueType
	Field   string
	Message string
}

type Result struct {
	Cert   *x509.Certificate
	Issues []Issue
}

func (r *Result) AddViolation(field, message string) {
	r.Issues = append(r.Issues, Issue{
		Field:   field,
		Type:    Violation,
		Message: message,
	})
}

func (r *Result) AddWarning(field, message string) {
	r.Issues = append(r.Issues, Issue{
		Field:   field,
		Type:    Warning,
		Message: message,
	})
}
