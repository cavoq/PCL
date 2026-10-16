package tests

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/testfiles"
)

// Output and errors of the lint command that policy suites cannot express.
func TestLintRun(t *testing.T) {
	tests := []struct {
		name     string
		cfg      linter.Config
		contains []string
		err      string
	}{
		{
			name: "text output",
			cfg: linter.Config{
				PolicyPaths:    []string{testfiles.Policies("leaf-keycertsign-fails.yaml")},
				CertPath:       testfiles.Certs(),
				ValidationTime: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
				OutputFmt:      "text",
				ShowMeta:       true,
			},
			contains: []string{
				"[Summary]", "Policy: integration-leaf-keycertsign-fails", "Cert: leaf", "Verdict:",
				"leaf-keycertsign-must-be-true",
			},
		},
		{
			name: "yaml output",
			cfg: linter.Config{
				PolicyPaths:    []string{testfiles.PolicyPacks("RFC5280.yaml")},
				CertPath:       testfiles.Certs("leaf.pem"),
				IssuerPaths:    []string{testfiles.Certs("intermediate.pem"), testfiles.Certs("root.pem")},
				ValidationTime: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
				OutputFmt:      "yaml",
				ShowMeta:       true,
			},
			contains: []string{
				"meta:", "total_certs: 3", "policy_id: rfc5280", "cert_type: leaf", "cert_type: intermediate",
				"cert_type: root", "verdict: pass",
			},
		},
		{
			name: "missing policy file",
			cfg:  linter.Config{PolicyPaths: []string{testfiles.Policies("missing.yaml")}, CertPath: testfiles.Certs(), OutputFmt: "text"},
			err:  "checking policy path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			err := linter.Run(test.cfg, &out)
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Fatalf("error = %v, want one containing %q", err, test.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("lint: %v", err)
			}
			for _, want := range test.contains {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output does not contain %q:\n%s", want, out.String())
				}
			}
		})
	}
}
