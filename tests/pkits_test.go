package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/operator"
	pathpkg "github.com/cavoq/PCL/internal/path"
)

// NIST PKITS 1.0.1 runs through the lint entry point. tests/pkits/manifest.json
// is generated from the PKITS description by tests/scripts/pkits-manifest.py.

const pkitsDir = "pkits"

// pkitsValidationTime lies inside the 2010-2030 validity of the PKITS data.
var pkitsValidationTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

type pkitsManifest struct {
	Tests []pkitsTest `json:"tests"`
}

type pkitsTest struct {
	ID      string     `json:"id"`
	Title   string     `json:"title"`
	EE      string     `json:"ee"`
	Issuers []string   `json:"issuers"`
	CRLs    []string   `json:"crls"`
	Runs    []pkitsRun `json:"runs"`
}

type pkitsRun struct {
	ExplicitPolicy       bool     `json:"explicitPolicy"`
	InitialPolicySet     []string `json:"initialPolicySet"`
	PolicyMappingInhibit bool     `json:"policyMappingInhibit"`
	AnyPolicyInhibit     bool     `json:"anyPolicyInhibit"`
	Expected             string   `json:"expected"`
}

func TestPKITS(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pkitsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read PKITS manifest: %v", err)
	}
	var manifest pkitsManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse PKITS manifest: %v", err)
	}
	if len(manifest.Tests) != 224 {
		t.Fatalf("PKITS manifest has %d tests, want 224", len(manifest.Tests))
	}

	suite := loadConformance(t, "PKITS", filepath.Join(pkitsDir, "known-gaps.yaml"))
	for _, test := range manifest.Tests {
		for index, run := range test.Runs {
			got, failures := runPKITS(t, test, run)
			suite.check(t, fmt.Sprintf("%s#%d", test.ID, index+1), got, run.Expected, failures)
		}
	}
	if conforming, gapped := suite.finish(t); conforming != 247 || gapped != 0 {
		t.Errorf("PKITS totals: %d conforming, %d known gaps; want 247, 0", conforming, gapped)
	}
}

// runPKITS lints one PKITS path with the run's policy inputs and reports
// "valid" when no error rule fails, together with the failed rules.
func runPKITS(t *testing.T, test pkitsTest, run pkitsRun) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	cfg := linter.Config{
		PolicyPaths:    []string{pathPolicy},
		CertPath:       filepath.Join(pkitsDir, test.EE),
		ValidationTime: pkitsValidationTime,
		TrustAnchorPaths: []string{
			filepath.Join(pkitsDir, test.Issuers[0]),
		},
		PathRevocation: pathpkg.RevocationRequired,
		CertificatePolicyInputs: operator.CertificatePolicyInputs{
			Configured:                  true,
			InitialPolicySet:            run.InitialPolicySet,
			InitialExplicitPolicy:       run.ExplicitPolicy,
			InitialPolicyMappingInhibit: run.PolicyMappingInhibit,
			InitialAnyPolicyInhibit:     run.AnyPolicyInhibit,
		},
	}
	for _, issuer := range test.Issuers[1:] {
		cfg.IssuerPaths = append(cfg.IssuerPaths, filepath.Join(pkitsDir, issuer))
	}
	// --crl takes one path, so the run's CRLs share a directory.
	for _, crlFile := range test.CRLs {
		data, err := os.ReadFile(filepath.Join(pkitsDir, crlFile))
		if err != nil {
			t.Fatal(err)
		}
		cfg.CRLPath = filepath.Dir(writeTestFile(t, dir, filepath.Base(crlFile), data))
	}

	valid, failures, err := lintAccepts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		return "valid", nil
	}
	return "invalid", failures
}
