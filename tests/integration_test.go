package tests

import (
	"testing"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/report"
	"github.com/cavoq/PCL/internal/utils"
)

func TestBSITR03116TSIntegration(t *testing.T) {
	certPath := "BSI-TR-03116-TS/certs"
	policyPath := "../policies/BSI-TR-03116-TS"

	certs, err := utils.GetCertificates(certPath)
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	policyChain, err := policy.GetPolicyChain(policyPath)
	if err != nil {
		t.Fatalf("Failed to load policy chain: %v", err)
	}

	l := &linter.Linter{}
	l.CreateJobs(certs, policyChain, certPath, policyPath)
	l.Execute()

	// Verify we have results
	if l.Run == nil {
		t.Fatal("Expected LintRun to be created")
	}

	if len(l.Run.Results) != len(certs) {
		t.Errorf("Expected %d results, got %d", len(certs), len(l.Run.Results))
	}

	// Test CLI reporter
	cliOutput, err := report.CliReporter{}.Report(l.Run)
	if err != nil {
		t.Fatalf("CLI reporter failed: %v", err)
	}
	t.Log("CLI Output:\n" + cliOutput)

	// Test JSON reporter
	jsonOutput, err := report.JsonReporter{}.Report(l.Run)
	if err != nil {
		t.Fatalf("JSON reporter failed: %v", err)
	}
	t.Log("JSON Output:\n" + jsonOutput)

	// Verify summary
	passed, failed, _ := l.Run.Summary()
	t.Logf("Summary: %d passed, %d failed", passed, failed)
}
