package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
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
	CRL      string            `yaml:"crl,omitempty"`
	OCSP     string            `yaml:"ocsp,omitempty"`
	EvalTime string            `yaml:"eval_time,omitempty"`
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
	crlPath := ""
	ocspPath := ""
	if tc.CRL != "" {
		crlPath = filepath.Join(testsDir, tc.CRL)
	}
	if tc.OCSP != "" {
		ocspPath = filepath.Join(testsDir, tc.OCSP)
	}
	var evalTime time.Time
	if tc.EvalTime != "" {
		parsed, err := time.Parse(time.RFC3339, tc.EvalTime)
		if err != nil {
			t.Fatalf("invalid eval_time %q: %v", tc.EvalTime, err)
		}
		evalTime = parsed
	}

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
	ctxOpts := make([]operator.ContextOption, 0)
	if crlPath != "" {
		crls, err := crl.GetCRLs(crlPath)
		if err != nil {
			t.Fatalf("unexpected CRL load error: %v", err)
		}
		ctxOpts = append(ctxOpts, operator.WithCRLs(crls))
	}
	if ocspPath != "" {
		ocsps, err := ocsp.GetOCSPs(ocspPath)
		if err != nil {
			t.Fatalf("unexpected OCSP load error: %v", err)
		}
		ctxOpts = append(ctxOpts, operator.WithOCSPs(ocsps))
	}

	for _, c := range chain {
		tree := zcrypto.BuildTree(c.Cert)
		ctx := operator.NewEvaluationContext(tree, c, chain, ctxOpts...)
		if !evalTime.IsZero() {
			ctx.Now = evalTime
		}
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
