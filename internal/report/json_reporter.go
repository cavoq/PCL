package report

import (
	"encoding/json"

	"github.com/cavoq/PCL/internal/linter"
)

type JsonReporter struct{}

func (j JsonReporter) Report(r *linter.LintResult) (string, error) {
	if r == nil {
		return `{"error": "no result"}`, nil
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
