package tests

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

// outputError reports lint output that is not the expected JSON.
type outputError struct{ error }

// lintResults runs the lint command like the CLI and returns every rule
// result. It does not use testing.T, so it is safe off the test goroutine; a
// run error is returned as is and unparsable output as an outputError.
func lintResults(cfg linter.Config) ([]policy.Result, error) {
	cfg.OutputFmt, cfg.Verbosity, cfg.ShowMeta = output.FormatJSON, 2, false
	var out bytes.Buffer
	if err := linter.Run(cfg, &out); err != nil {
		return nil, err
	}
	var results []policy.Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		return nil, outputError{fmt.Errorf("parse lint output: %w\n%s", err, out.String())}
	}
	return results, nil
}

// lintAccepts lints cfg and reports whether no error-severity rule fails for
// any evaluated input, with the failed rules as "certType:ruleID". A run
// error rejects the input and is its only failure; only unparsable output is
// returned as an error.
func lintAccepts(cfg linter.Config) (bool, []string, error) {
	results, err := lintResults(cfg)
	if errors.As(err, new(outputError)) {
		return false, nil, err
	}
	if err != nil {
		return false, []string{"error: " + err.Error()}, nil
	}
	var failures []string
	for _, result := range results {
		for _, ruleResult := range result.Results {
			if ruleResult.Verdict == rule.VerdictFail && ruleResult.Severity == rule.SeverityError {
				failures = append(failures, result.CertType+":"+ruleResult.RuleID)
			}
		}
	}
	sort.Strings(failures)
	return len(failures) == 0, failures, nil
}

// writeTestFile writes data to name in dir and returns the path.
func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
