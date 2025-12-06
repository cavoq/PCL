package report

import (
	"encoding/json"

	"github.com/cavoq/PCL/internal/linter"
)

type JsonReporter struct{}

func (j JsonReporter) Report(run *linter.LintRun) (string, error) {
	if run == nil {
		return `{"error": "no lint run"}`, nil
	}
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
