package tests

import (
	"crypto/x509"
	"encoding/pem"

	"os"
	"testing"

	"github.com/cavoq/RCV/internal/linter"
	"github.com/cavoq/RCV/internal/policy"
	"github.com/cavoq/RCV/internal/report"

	"gopkg.in/yaml.v3"
)

func TestLintLeafCertificate(t *testing.T) {
	certPEM, err := os.ReadFile("BSI-TR-03116-TS/certs/leaf.pem")
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	policyData, err := os.ReadFile("../policies/BSI-TR-03116-TS/leaf.yaml")
	if err != nil {
		t.Fatalf("Failed to read policy: %v", err)
	}

	var pol policy.Policy
	if err := yaml.Unmarshal(policyData, &pol); err != nil {
		t.Fatalf("Failed to unmarshal policy YAML: %v", err)
	}

	l := linter.NewLinter(cert, &pol)
	result, err := l.LintAll()
	if err != nil {
		t.Fatalf("Linting failed: %v", err)
	}

	reportStr, err := report.JsonReporter{}.Report(result)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}
	t.Log(reportStr)
}
