package tests

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/output"
)

func TestLinterRunIntegration(t *testing.T) {
	t.Run("certificate chain json output", func(t *testing.T) {
		var buf bytes.Buffer
		err := linter.Run(linter.Config{
			PolicyPaths: []string{filepath.Join("policies", "basic.yaml")},
			CertPath:    "certs",
			OutputFmt:   "json",
			Verbosity:   2,
			ShowMeta:    true,
		}, &buf)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}

		var got output.LintOutput
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("failed to decode JSON output: %v\n%s", err, buf.String())
		}

		if got.Meta.TotalCerts != 3 {
			t.Fatalf("TotalCerts = %d, want 3", got.Meta.TotalCerts)
		}
		if got.Meta.TotalRules != 12 {
			t.Fatalf("TotalRules = %d, want 12", got.Meta.TotalRules)
		}
		if got.Meta.PassedRules != 7 {
			t.Fatalf("PassedRules = %d, want 7", got.Meta.PassedRules)
		}
		if got.Meta.FailedRules != 0 {
			t.Fatalf("FailedRules = %d, want 0", got.Meta.FailedRules)
		}
		if got.Meta.SkippedRules != 5 {
			t.Fatalf("SkippedRules = %d, want 5", got.Meta.SkippedRules)
		}
		if len(got.Results) != 3 {
			t.Fatalf("got %d results, want 3", len(got.Results))
		}

		seen := map[string]bool{}
		for _, result := range got.Results {
			seen[result.CertType] = true
			if result.PolicyID != "integration-basic" {
				t.Fatalf("PolicyID = %q, want integration-basic", result.PolicyID)
			}
			if result.Verdict != "pass" {
				t.Fatalf("cert %s verdict = %q, want pass", result.CertType, result.Verdict)
			}
			if len(result.Results) != 4 {
				t.Fatalf("cert %s has %d rules, want 4", result.CertType, len(result.Results))
			}
		}

		for _, certType := range []string{"leaf", "intermediate", "root"} {
			if !seen[certType] {
				t.Fatalf("missing result for cert type %q", certType)
			}
		}
	})

	t.Run("certificate chain text output", func(t *testing.T) {
		var buf bytes.Buffer
		err := linter.Run(linter.Config{
			PolicyPaths: []string{filepath.Join("policies", "leaf-keycertsign-fails.yaml")},
			CertPath:    "certs",
			OutputFmt:   "text",
			ShowMeta:    true,
		}, &buf)
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}

		out := buf.String()
		for _, want := range []string{
			"[Summary]",
			"Policy: integration-leaf-keycertsign-fails",
			"Cert: leaf",
			"Verdict:",
			"leaf-keycertsign-must-be-true",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("text output missing %q\n%s", want, out)
			}
		}
	})

	t.Run("missing policy returns error", func(t *testing.T) {
		var buf bytes.Buffer
		err := linter.Run(linter.Config{
			PolicyPaths: []string{filepath.Join("policies", "missing.yaml")},
			CertPath:    "certs",
			OutputFmt:   "json",
		}, &buf)
		if err == nil {
			t.Fatal("expected missing policy to return error")
		}
		if !strings.Contains(err.Error(), "checking policy path") {
			t.Fatalf("error = %q, want policy path context", err.Error())
		}
	})
}
