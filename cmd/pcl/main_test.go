package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cavoq/PCL/internal/linter"
	pathpkg "github.com/cavoq/PCL/internal/path"
)

func TestRootCommandAcceptsApplicationPurpose(t *testing.T) {
	var config linter.Config
	command := newRootCmd(&config)

	if err := command.ParseFlags([]string{"--purpose", "serverAuth"}); err != nil {
		t.Fatalf("parse --purpose: %v", err)
	}
	if config.ApplicationPurpose != "serverAuth" {
		t.Fatalf("ApplicationPurpose = %q, want serverAuth", config.ApplicationPurpose)
	}
}

func TestRootCommandAcceptsCertificatePolicyInputs(t *testing.T) {
	var config linter.Config
	command := newRootCmd(&config)

	if err := command.ParseFlags([]string{
		"--initial-policy-set", "1.2.3.4,1.2.3.5",
		"--initial-explicit-policy",
		"--initial-policy-mapping-inhibit",
		"--initial-any-policy-inhibit",
	}); err != nil {
		t.Fatalf("parse certificate policy inputs: %v", err)
	}
	markCertificatePolicyInputsConfigured(command.Flags(), &config)
	inputs := config.CertificatePolicyInputs
	if !inputs.Configured || len(inputs.InitialPolicySet) != 2 ||
		!inputs.InitialExplicitPolicy || !inputs.InitialPolicyMappingInhibit ||
		!inputs.InitialAnyPolicyInhibit {
		t.Fatalf("CertificatePolicyInputs = %#v", inputs)
	}
}

func TestRootCommandAcceptsPathValidationInputs(t *testing.T) {
	var config linter.Config
	command := newRootCmd(&config)
	if err := command.ParseFlags([]string{
		"--trust-anchor", "root.pem",
		"--max-path-length", "0",
		"--path-revocation", "required",
	}); err != nil {
		t.Fatalf("parse path validation inputs: %v", err)
	}
	markPathInputsConfigured(command.Flags(), &config)
	if len(config.TrustAnchorPaths) != 1 || config.TrustAnchorPaths[0] != "root.pem" ||
		!config.MaximumPathLengthConfigured || config.MaximumPathLength != 0 ||
		config.PathRevocation != "required" {
		t.Fatalf("path validation config = %#v", config)
	}
}

func TestRootCommandAcceptsDetails(t *testing.T) {
	var config linter.Config
	command := newRootCmd(&config)

	if err := command.ParseFlags([]string{"--details"}); err != nil {
		t.Fatalf("parse --details: %v", err)
	}
	if !config.ShowDetails {
		t.Fatal("ShowDetails = false, want true")
	}
}

func TestInspectCommandSharesInputFlags(t *testing.T) {
	command := newInspectCmd()
	if err := command.ParseFlags([]string{"--cert", "leaf.pem", "--crl", "list.crl", "--purpose", "serverAuth", "--paths", "--output", "json"}); err != nil {
		t.Fatalf("parse inspect flags: %v", err)
	}
	for _, name := range []string{"cert", "issuer", "crl", "ocsp", "auto-validate", "paths", "output"} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("inspect is missing --%s", name)
		}
	}
	if command.Flags().Lookup("policy") != nil {
		t.Error("inspect must not accept --policy")
	}
	for _, name := range []string{"trust-anchor", "max-path-length", "path-revocation"} {
		if command.Flags().Lookup(name) != nil {
			t.Errorf("inspect must not accept --%s", name)
		}
	}
}

func TestSchemaCommandPrintsCommittedSchema(t *testing.T) {
	var out bytes.Buffer
	command := newSchemaCmd()
	command.SetOut(&out)
	command.SetArgs(nil)
	if err := command.Execute(); err != nil {
		t.Fatalf("schema command: %v", err)
	}
	committed, err := os.ReadFile("../../schemas/policy.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), committed) {
		t.Fatal("pcl schema output differs from schemas/policy.schema.json")
	}
}

func TestTestCommandRunsExampleSuites(t *testing.T) {
	var out bytes.Buffer
	command := newTestCmd()
	command.SetOut(&out)
	command.SetArgs([]string{"../../tests/policy-suites"})
	if err := command.Execute(); err != nil {
		t.Fatalf("test command: %v\n%s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(" passed, 0 failed")) {
		t.Fatalf("unexpected report:\n%s", out.String())
	}
}

func TestRuntimeErrorsDoNotPrintUsage(t *testing.T) {
	execute := func(args ...string) (string, error) {
		var opts linter.Config
		root := newRootCmd(&opts)
		root.AddCommand(newInspectCmd())
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		err := root.Execute()
		return out.String(), err
	}

	output, err := execute("inspect", "--issuer", "root.pem")
	if err == nil {
		t.Fatal("expected a runtime error")
	}
	if strings.Contains(output, "Usage:") || strings.Contains(output, "Error:") {
		t.Fatalf("runtime error printed usage or the error itself:\n%s", output)
	}

	output, err = execute("inspect", "--bogus")
	if err == nil {
		t.Fatal("expected a flag error")
	}
	if !strings.Contains(output, "Usage:") {
		t.Fatalf("flag error should print usage:\n%s", output)
	}
}

// Policy tests and inspection see the same external data as a lint run.
func TestEvaluatingCommandsLoadPublicSuffixList(t *testing.T) {
	dir := t.TempDir()
	certs, err := filepath.Abs("../../tests/certs")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"psl.dat": "// ===BEGIN ICANN DOMAINS===\ntest\n// ===END ICANN DOMAINS===\n",
		"policy.yaml": `id: psl
version: "1"
rules:
  - id: san-tld-registered
    target: certificate.subjectAltName.dNSName.0
    operator: tldRegistered
    severity: error
`,
		"psl.test.yaml": `policy: policy.yaml
time: 2026-10-01
tests:
  - name: leaf.example.test has a registered TLD
    cert: ` + filepath.Join(certs, "leaf.pem") + `
    expect:
      - input: leaf
        rules:
          san-tld-registered: pass
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	command := newTestCmd()
	command.SetOut(&out)
	command.SetErr(&out)
	command.SetArgs([]string{"--psl-file", filepath.Join(dir, "psl.dat"), dir})
	if err := command.Execute(); err != nil {
		t.Fatalf("test command: %v\n%s", err, out.String())
	}

	for _, command := range []*cobra.Command{newInspectCmd(), newTestCmd()} {
		for _, name := range []string{"psl-file", "use-psl", "data-dir"} {
			if command.Flags().Lookup(name) == nil {
				t.Errorf("%s is missing --%s", command.Name(), name)
			}
		}
	}
}

func TestColorOutput(t *testing.T) {
	device, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()
	file, err := os.Create(filepath.Join(t.TempDir(), "results.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	t.Setenv("NO_COLOR", "")
	if !colorOutput(device) {
		t.Error("a character device should get colors")
	}
	if colorOutput(file) || colorOutput(&bytes.Buffer{}) {
		t.Error("files and buffers should not get colors")
	}
	t.Setenv("NO_COLOR", "1")
	if colorOutput(device) {
		t.Error("NO_COLOR should disable colors")
	}
}

func TestDataOptionsLoad(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.dat")

	var warnings bytes.Buffer
	if err := (dataOptions{UsePSL: true, DataDir: t.TempDir()}).load(&warnings); err != nil || warnings.Len() != 0 {
		t.Errorf("default list missing: error %v, warnings %q; want neither", err, warnings.String())
	}
	if err := (dataOptions{PSLFile: missing}).load(&warnings); err == nil || !strings.Contains(err.Error(), "--psl-file") {
		t.Errorf("missing --psl-file: error = %v, want it reported", err)
	}
}

func TestRootCommandDefaultsToDomainRevocationMode(t *testing.T) {
	var config linter.Config
	command := newRootCmd(&config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if config.PathRevocation != pathpkg.DefaultRevocationMode {
		t.Fatalf("--path-revocation defaults to %q, want %q", config.PathRevocation, pathpkg.DefaultRevocationMode)
	}
}
