package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/cavoq/PCL/internal/linter"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// The golden tests run the pcl command tree on the NIST PKITS data, which is
// vendored and never regenerated, with the built-in policies, the embedded
// Public Suffix List and a fixed --validation-time for lint and inspect runs.
// A golden file holds the output, then any error; only the run timestamp is
// masked.
const (
	pkitsCerts = "../../tests/pkits/certs/"
	pkitsCRLs  = "testdata/pkits-crls"
)

const goldenTime = "2020-01-01T00:00:00Z"

// checkedAt matches the run timestamp in text, JSON and YAML output.
var checkedAt = regexp.MustCompile(`(Checked: |"checked_at": "|checked_at: )[0-9][0-9T:.+\- Z]*[0-9Z]`)

func TestGolden(t *testing.T) {
	validPath := []string{
		"--cert", pkitsCerts + "ValidCertificatePathTest1EE.crt",
		"--issuer", pkitsCerts + "GoodCACert.crt",
		"--trust-anchor", pkitsCerts + "TrustAnchorRootCertificate.crt",
		"--crl", pkitsCRLs,
		"--path-revocation", "required",
	}
	invalidSignature := []string{
		"--cert", pkitsCerts + "InvalidEESignatureTest3EE.crt",
		"--issuer", pkitsCerts + "GoodCACert.crt",
		"--trust-anchor", pkitsCerts + "TrustAnchorRootCertificate.crt",
		"--crl", pkitsCRLs,
		"--path-revocation", "required",
	}
	tests := []struct {
		name string
		args []string
	}{
		{"lint-text-details", append([]string{"--policy", "rfc5280", "--details", "-v"}, validPath...)},
		{"lint-json", append([]string{"--policy", "rfc5280", "--output", "json", "-v"}, validPath...)},
		{"lint-yaml", append([]string{"--policy", "rfc5280", "--output", "yaml", "-v"}, validPath...)},
		{"lint-invalid-signature", append([]string{"--policy", "rfc5280", "--details", "--fail-on", "error"}, invalidSignature...)},
		// The PKITS certificates expire at the end of 2030.
		{"lint-validation-time-expired", append([]string{"--policy", "rfc5280", "--details", "--fail-on", "error",
			"--validation-time", "2031-01-01"}, validPath...)},
		{"lint-other-builtins", []string{"--policy", "local-profile", "--policy", "tr03116-tls-server",
			"--cert", pkitsCerts + "ValidCertificatePathTest1EE.crt", "--issuer", pkitsCerts + "GoodCACert.crt", "-v"}},
		// psl-leaf.pem is a static copy outside tests/fixturegen, so it never
		// changes; its SAN is leaf.example.test.
		{"lint-embedded-psl", []string{"--policy", "testdata/psl-probe.yaml", "--cert", "testdata/psl-leaf.pem", "-v", "--details"}},
		{"inspect-tree", []string{"inspect", "--cert", pkitsCerts + "ValidCertificatePathTest1EE.crt"}},
		{"inspect-paths", []string{"inspect", "--paths", "--cert", pkitsCerts + "ValidCertificatePathTest1EE.crt",
			"--crl", pkitsCRLs + "/GoodCACRL.crl"}},
		{"policies", []string{"policies"}},
		{"policies-show-rfc4055", []string{"policies", "show", "rfc4055"}},
		{"test-path-suite", []string{"test", "../../tests/policy-suites/path.test.yaml"}},
		{"error-unknown-builtin", []string{"--policy", "builtin:nope", "--cert", pkitsCerts + "GoodCACert.crt"}},
		{"error-peer-name-without-anchor", []string{"--policy", "rfc5280", "--peer-name", "example.com",
			"--cert", pkitsCerts + "GoodCACert.crt"}},
	}

	dataDir := t.TempDir()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config linter.Config
			command := newApp(&config)
			var out bytes.Buffer
			command.SetOut(&out)
			command.SetErr(&out)
			args := test.args
			if test.name != "policies" && test.name != "policies-show-rfc4055" {
				// An empty data directory selects the embedded PSL snapshot.
				args = append(args, "--data-dir", dataDir)
			}
			if !slices.Contains(args, "--validation-time") && lintsOrInspects(args) {
				args = append(args, "--validation-time", goldenTime)
			}
			command.SetArgs(args)
			if err := command.Execute(); err != nil {
				out.WriteString("error: " + err.Error() + "\n")
			}
			got := checkedAt.ReplaceAll(out.Bytes(), []byte("${1}<time>"))

			path := filepath.Join("testdata", "golden", test.name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v; run make golden", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output differs from %s; run make golden and review the diff\n%s", path, got)
			}
		})
	}
}

// lintsOrInspects reports whether args run a lint or pcl inspect, the
// commands that take --validation-time.
func lintsOrInspects(args []string) bool {
	return args[0] != "policies" && args[0] != "test"
}
