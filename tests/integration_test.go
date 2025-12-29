package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"gopkg.in/yaml.v3"
)

func TestIntegrationPolicies(t *testing.T) {
	caseFiles, err := filepath.Glob(filepath.Join("cases", "*.yaml"))
	if err != nil {
		t.Fatalf("unexpected glob error: %v", err)
	}
	if len(caseFiles) == 0 {
		t.Fatalf("no test cases found")
	}

	for _, caseFile := range caseFiles {
		tc, err := loadCase(caseFile)
		if err != nil {
			t.Fatalf("failed to load case %s: %v", caseFile, err)
		}
		t.Run(tc.Name, func(t *testing.T) {
			runCase(t, filepath.Dir(caseFile), tc)
		})
	}
}

type testCase struct {
	Name     string            `yaml:"name"`
	Policy   string            `yaml:"policy"`
	Certs    string            `yaml:"certs"`
	Expected map[string]counts `yaml:"expected"`
}

type counts struct {
	Pass int `yaml:"pass"`
	Fail int `yaml:"fail"`
	Skip int `yaml:"skip"`
}

func loadCase(path string) (testCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return testCase{}, err
	}
	var tc testCase
	if err := yaml.Unmarshal(data, &tc); err != nil {
		return testCase{}, err
	}
	if tc.Name == "" {
		tc.Name = filepath.Base(path)
	}
	return tc, nil
}

func runCase(t *testing.T, caseDir string, tc testCase) {
	t.Helper()

	testsDir := filepath.Dir(caseDir)
	policyPath := filepath.Join(testsDir, tc.Policy)
	certsPath := filepath.Join(testsDir, tc.Certs)

	p, err := policy.ParseFile(policyPath)
	if err != nil {
		t.Fatalf("unexpected policy parse error: %v", err)
	}

	certs, err := cert.LoadCertificates(certsPath)
	if err != nil {
		t.Fatalf("unexpected cert load error: %v", err)
	}

	chain, err := cert.BuildChain(certs)
	if err != nil {
		t.Fatalf("unexpected chain error: %v", err)
	}

	reg := operator.DefaultRegistry()
	results := make([]policy.Result, 0, len(chain))

	for _, c := range chain {
		tree := zcrypto.BuildTree(c.Cert)
		ctx := operator.NewEvaluationContext(tree, c, chain)
		results = append(results, policy.Evaluate(p, tree, reg, ctx))
	}

	if len(results) != len(tc.Expected) {
		t.Fatalf("expected %d results, got %d", len(tc.Expected), len(results))
	}

	for _, res := range results {
		counts := countVerdicts(res.Results)
		want, ok := tc.Expected[res.CertType]
		if !ok {
			t.Fatalf("unexpected cert type %q", res.CertType)
		}
		if counts != want {
			t.Fatalf("cert %s: expected %+v, got %+v", res.CertType, want, counts)
		}
	}
}

func countVerdicts(results []rule.Result) counts {
	var c counts
	for _, r := range results {
		switch r.Verdict {
		case rule.VerdictPass:
			c.Pass++
		case rule.VerdictFail:
			c.Fail++
		case rule.VerdictSkip:
			c.Skip++
		}
	}
	return c
}
