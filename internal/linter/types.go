package linter

import "crypto/x509"

type IssueType string
type ScopeType string

const (
	Violation  IssueType = "violation"
	Warning    IssueType = "warning"
	Semantic   ScopeType = "semantic"
	Functional ScopeType = "functional"
)

type Issue struct {
	Type    IssueType
	Field   string
	Message string
	Scope   ScopeType
}

type Result struct {
	Cert   *x509.Certificate
	Issues []Issue
}

func (r *Result) AddViolation(field, message string, scope ScopeType) {
	r.Issues = append(r.Issues, Issue{
		Type:    Violation,
		Field:   field,
		Message: message,
		Scope:   scope,
	})
}

func (r *Result) AddWarning(field, message string, scope ScopeType) {
	r.Issues = append(r.Issues, Issue{
		Type:    Warning,
		Field:   field,
		Message: message,
		Scope:   scope,
	})
}
