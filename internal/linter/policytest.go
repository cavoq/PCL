package linter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/evaluator"
	"github.com/cavoq/PCL/internal/operator"
	pathpkg "github.com/cavoq/PCL/internal/path"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

// PolicyTestSuffix marks policy test suite files inside directories.
const PolicyTestSuffix = ".test.yaml"

// policySuite is a policy test file. Paths are relative to the file.
type policySuite struct {
	Policy policyPaths      `yaml:"policy"`
	Time   string           `yaml:"time,omitempty"`
	Tests  []policyTestCase `yaml:"tests"`
}

// policyPaths accepts one path or a list of paths.
type policyPaths []string

func (paths *policyPaths) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*paths = policyPaths{value.Value}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return err
	}
	*paths = list
	return nil
}

type policyTestCase struct {
	Name                    string                      `yaml:"name"`
	Cert                    string                      `yaml:"cert,omitempty"`
	Issuers                 []string                    `yaml:"issuers,omitempty"`
	TrustAnchors            []string                    `yaml:"trustAnchors,omitempty"`
	CRL                     string                      `yaml:"crl,omitempty"`
	OCSP                    string                      `yaml:"ocsp,omitempty"`
	Purpose                 string                      `yaml:"purpose,omitempty"`
	PeerNames               []string                    `yaml:"peerNames,omitempty"`
	CertificatePolicyInputs *policyTestCertificateInput `yaml:"certificatePolicyInputs,omitempty"`
	MaximumPathLength       *int                        `yaml:"maximumPathLength,omitempty"`
	PathRevocation          string                      `yaml:"pathRevocation,omitempty"`
	Time                    string                      `yaml:"time,omitempty"`
	Error                   string                      `yaml:"error,omitempty"`
	Expect                  []policyExpectation         `yaml:"expect,omitempty"`
}

type policyTestCertificateInput struct {
	InitialPolicySet            []string `yaml:"initialPolicySet,omitempty"`
	InitialExplicitPolicy       bool     `yaml:"initialExplicitPolicy,omitempty"`
	InitialPolicyMappingInhibit bool     `yaml:"initialPolicyMappingInhibit,omitempty"`
	InitialAnyPolicyInhibit     bool     `yaml:"initialAnyPolicyInhibit,omitempty"`
}

func (inputs *policyTestCertificateInput) operatorInputs() operator.CertificatePolicyInputs {
	if inputs == nil {
		return operator.CertificatePolicyInputs{}
	}
	return operator.CertificatePolicyInputs{
		Configured:                  true,
		InitialPolicySet:            inputs.InitialPolicySet,
		InitialExplicitPolicy:       inputs.InitialExplicitPolicy,
		InitialPolicyMappingInhibit: inputs.InitialPolicyMappingInhibit,
		InitialAnyPolicyInhibit:     inputs.InitialAnyPolicyInhibit,
	}
}

// policyExpectation states the verdicts expected for one evaluated input,
// selected by its role (leaf, intermediate, root, ocspSigning) or input type
// (crl, ocsp) and optionally by policy id. Failed, when set, lists exactly
// the rules that fail for the input; an empty list expects that none fails.
type policyExpectation struct {
	Input   string            `yaml:"input"`
	Policy  string            `yaml:"policy,omitempty"`
	Verdict string            `yaml:"verdict,omitempty"`
	Rules   map[string]string `yaml:"rules,omitempty"`
	Failed  *[]string         `yaml:"failed,omitempty"`
}

// PolicyTestSummary counts the cases of a policy test run.
type PolicyTestSummary struct {
	Passed int
	Failed int
}

// RunPolicyTests runs every policy test suite in paths (files, or
// directories searched for *.test.yaml) and reports each case to w. Each case
// is linted exactly like the lint command with the suite's policies.
func RunPolicyTests(paths []string, w io.Writer) (PolicyTestSummary, error) {
	files, err := policySuiteFiles(paths)
	if err != nil {
		return PolicyTestSummary{}, err
	}
	if len(files) == 0 {
		return PolicyTestSummary{}, fmt.Errorf("no policy test files (*%s) found", PolicyTestSuffix)
	}

	var summary PolicyTestSummary
	for _, file := range files {
		if err := runPolicySuite(file, w, &summary); err != nil {
			return summary, fmt.Errorf("%s: %w", file, err)
		}
	}
	_, err = fmt.Fprintf(w, "\n%d passed, %d failed\n", summary.Passed, summary.Failed)
	return summary, err
}

func policySuiteFiles(paths []string) ([]string, error) {
	var files []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		err = filepath.WalkDir(path, func(candidate string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(candidate, PolicyTestSuffix) {
				files = append(files, candidate)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

func runPolicySuite(file string, w io.Writer, summary *PolicyTestSummary) error {
	suite, err := loadPolicySuite(file)
	if err != nil {
		return err
	}
	dir := filepath.Dir(file)
	registry := operator.DefaultRegistry()
	policyPaths := make([]string, 0, len(suite.Policy))
	for _, path := range suite.Policy {
		policyPaths = append(policyPaths, resolvePolicyPath(dir, path))
	}
	policies, err := loadPolicies(policyPaths, registry)
	if err != nil {
		return err
	}

	for _, testCase := range suite.Tests {
		failures := runPolicyTestCase(dir, suite, testCase, policies, registry)
		status := "PASS"
		if len(failures) > 0 {
			status = "FAIL"
			summary.Failed++
		} else {
			summary.Passed++
		}
		if _, err := fmt.Fprintf(w, "%s  %s  %s\n", status, file, testCase.Name); err != nil {
			return err
		}
		for _, failure := range failures {
			if _, err := fmt.Fprintf(w, "      %s\n", failure); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadPolicySuite(file string) (policySuite, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return policySuite{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var suite policySuite
	if err := decoder.Decode(&suite); err != nil {
		return policySuite{}, fmt.Errorf("parsing test file: %w", err)
	}
	if len(suite.Policy) == 0 {
		return policySuite{}, errors.New("policy is required")
	}
	if len(suite.Tests) == 0 {
		return policySuite{}, errors.New("tests must not be empty")
	}
	for index, testCase := range suite.Tests {
		if strings.TrimSpace(testCase.Name) == "" {
			return policySuite{}, fmt.Errorf("test %d: name is required", index)
		}
		if testCase.Error == "" && len(testCase.Expect) == 0 {
			return policySuite{}, fmt.Errorf("test %q: expect or error is required", testCase.Name)
		}
		for _, expectation := range testCase.Expect {
			if err := validateExpectation(expectation); err != nil {
				return policySuite{}, fmt.Errorf("test %q: %w", testCase.Name, err)
			}
		}
	}
	return suite, nil
}

func validateExpectation(expectation policyExpectation) error {
	if expectation.Input == "" {
		return errors.New("expect: input is required")
	}
	if expectation.Verdict == "" && len(expectation.Rules) == 0 && expectation.Failed == nil {
		return fmt.Errorf("expect %s: verdict, rules or failed is required", expectation.Input)
	}
	switch expectation.Verdict {
	case "", rule.VerdictPass, rule.VerdictFail, rule.VerdictInconclusive, policy.VerdictNotApplicable:
	default:
		return fmt.Errorf("expect %s: verdict must be pass, fail, inconclusive or not_applicable", expectation.Input)
	}
	for ruleID, verdict := range expectation.Rules {
		switch verdict {
		case rule.VerdictPass, rule.VerdictFail, rule.VerdictSkip, rule.VerdictInconclusive:
		default:
			return fmt.Errorf("expect %s: rule %s verdict must be pass, fail, skip or inconclusive", expectation.Input, ruleID)
		}
	}
	return nil
}

// runPolicyTestCase lints one case and returns its failed expectations.
func runPolicyTestCase(
	dir string,
	suite policySuite,
	testCase policyTestCase,
	policies []policy.Policy,
	registry *operator.Registry,
) []string {
	results, err := lintPolicyTestCase(dir, suite, testCase, policies, registry)
	if testCase.Error != "" {
		switch {
		case err == nil:
			return []string{fmt.Sprintf("expected an error containing %q", testCase.Error)}
		case !strings.Contains(err.Error(), testCase.Error):
			return []string{fmt.Sprintf("error %q does not contain %q", err, testCase.Error)}
		}
		return nil
	}
	if err != nil {
		return []string{"error: " + err.Error()}
	}

	var failures []string
	for _, expectation := range testCase.Expect {
		failures = append(failures, checkExpectation(expectation, results)...)
	}
	return failures
}

func lintPolicyTestCase(
	dir string,
	suite policySuite,
	testCase policyTestCase,
	policies []policy.Policy,
	registry *operator.Registry,
) ([]policy.Result, error) {
	evaluationTime, err := parsePolicyTestTime(testCase.Time, suite.Time)
	if err != nil {
		return nil, err
	}
	cfg := Config{
		CertPath:                resolvePath(dir, testCase.Cert),
		IssuerPaths:             resolvePaths(dir, testCase.Issuers),
		TrustAnchorPaths:        resolvePaths(dir, testCase.TrustAnchors),
		CRLPath:                 resolvePath(dir, testCase.CRL),
		OCSPPath:                resolvePath(dir, testCase.OCSP),
		ApplicationPurpose:      testCase.Purpose,
		PeerNames:               testCase.PeerNames,
		CertificatePolicyInputs: testCase.CertificatePolicyInputs.operatorInputs(),
		ValidationTime:          evaluationTime,
		PathRevocation:          pathpkg.RevocationMode(testCase.PathRevocation),
	}
	if testCase.MaximumPathLength != nil {
		cfg.MaximumPathLength = *testCase.MaximumPathLength
		cfg.MaximumPathLengthConfigured = true
	}
	applyDefaults(&cfg)
	if err := cfg.validateInputs(); err != nil {
		return nil, err
	}

	var cleanups cleanupStack
	defer cleanups.Close()
	inputs, err := acquireInputs(cfg, io.Discard, &cleanups)
	if err != nil {
		return nil, err
	}
	return evaluator.Evaluate(buildSubjects(cfg, inputs, policies, registry), registry), nil
}

// parsePolicyTestTime returns the case time, else the suite time, as
// RFC 3339 or YYYY-MM-DD (UTC midnight). Without either it is zero, which
// lints at the current time.
func parsePolicyTestTime(caseTime, suiteTime string) (time.Time, error) {
	value := caseTime
	if value == "" {
		value = suiteTime
	}
	if value == "" {
		return time.Time{}, nil
	}
	return ParseEvaluationTime(value)
}

// ParseEvaluationTime parses an evaluation time given as RFC 3339 or
// YYYY-MM-DD (UTC midnight).
func ParseEvaluationTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("time %q is not RFC 3339 or YYYY-MM-DD", value)
}

// checkExpectation compares the results for one input with expectation.
func checkExpectation(expectation policyExpectation, results []policy.Result) []string {
	label := expectation.Input
	if expectation.Policy != "" {
		label += " (" + expectation.Policy + ")"
	}

	matched := matchingResults(expectation, results)
	if len(matched) == 0 {
		return []string{fmt.Sprintf("%s: no policy evaluated this input", label)}
	}

	var failures []string
	if expectation.Verdict != "" {
		for _, result := range matched {
			if result.Verdict != expectation.Verdict {
				failures = append(failures, fmt.Sprintf("%s: policy %s verdict %s, want %s",
					label, result.PolicyID, result.Verdict, expectation.Verdict))
			}
		}
	}

	ruleIDs := make([]string, 0, len(expectation.Rules))
	for ruleID := range expectation.Rules {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		failures = append(failures, checkRuleVerdict(label, ruleID, expectation.Rules[ruleID], matched)...)
	}
	if expectation.Failed != nil {
		got, want := failedRuleIDs(matched), sortedUnique(*expectation.Failed)
		if !slices.Equal(got, want) {
			failures = append(failures, fmt.Sprintf("%s: failed rules [%s], want [%s]",
				label, strings.Join(got, ", "), strings.Join(want, ", ")))
		}
	}
	return failures
}

// failedRuleIDs returns the sorted IDs of the rules that fail in results.
func failedRuleIDs(results []policy.Result) []string {
	var ruleIDs []string
	for _, result := range results {
		for _, ruleResult := range result.Results {
			if ruleResult.Verdict == rule.VerdictFail {
				ruleIDs = append(ruleIDs, ruleResult.RuleID)
			}
		}
	}
	return sortedUnique(ruleIDs)
}

func sortedUnique(values []string) []string {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

func matchingResults(expectation policyExpectation, results []policy.Result) []policy.Result {
	var matched []policy.Result
	for _, result := range results {
		if result.CertType == expectation.Input &&
			(expectation.Policy == "" || result.PolicyID == expectation.Policy) {
			matched = append(matched, result)
		}
	}
	return matched
}

// checkRuleVerdict compares every evaluation of ruleID in matched with want.
func checkRuleVerdict(label, ruleID, want string, matched []policy.Result) []string {
	var failures []string
	found := false
	for _, result := range matched {
		for _, ruleResult := range result.Results {
			if ruleResult.RuleID != ruleID {
				continue
			}
			found = true
			if ruleResult.Verdict == want {
				continue
			}
			failure := fmt.Sprintf("%s: rule %s %s, want %s", label, ruleID, ruleResult.Verdict, want)
			if ruleResult.Message != "" {
				failure += " (" + ruleResult.Message + ")"
			}
			failures = append(failures, failure)
		}
	}
	if !found {
		failures = append(failures, fmt.Sprintf("%s: rule %s was not evaluated", label, ruleID))
	}
	return failures
}

func resolvePath(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func resolvePaths(dir string, paths []string) []string {
	resolved := make([]string, 0, len(paths))
	for _, path := range paths {
		resolved = append(resolved, resolvePath(dir, path))
	}
	return resolved
}
