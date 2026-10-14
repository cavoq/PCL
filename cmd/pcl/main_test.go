package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/linter"
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
