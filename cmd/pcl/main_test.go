package main

import (
	"bytes"
	"os"
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
