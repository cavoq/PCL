package tests

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/certparse"
	"github.com/cavoq/PCL/internal/linter"
	"github.com/cavoq/PCL/internal/output"
	pathpkg "github.com/cavoq/PCL/internal/path"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
)

// x509-limbo runs through the lint entry point with the limbo path policy and
// the shipped RFC 5280 profile. tests/limbo/limbo.json is not committed; fetch
// it with tests/scripts/fetch-limbo.sh. PCL_REQUIRE_LIMBO=1 turns a missing
// file into a failure.

const limboDir = "limbo"

// limboValidationTime stands in for "now" in testcases without a validation
// time. It lies inside the 2026-01-19 to 2027-01-21 validity of the pinned
// BetterTLS certificates; revisit it when re-pinning limbo.
var limboValidationTime = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

type limboSuite struct {
	Version   int         `json:"version"`
	Testcases []limboCase `json:"testcases"`
}

type limboCase struct {
	ID                     string          `json:"id"`
	TrustedCerts           []string        `json:"trusted_certs"`
	UntrustedIntermediates []string        `json:"untrusted_intermediates"`
	PeerCertificate        string          `json:"peer_certificate"`
	ValidationTime         *time.Time      `json:"validation_time"`
	ExtendedKeyUsage       []string        `json:"extended_key_usage"`
	ExpectedResult         string          `json:"expected_result"`
	ExpectedPeerName       *limboPeerName  `json:"expected_peer_name"`
	ExpectedPeerNames      []limboPeerName `json:"expected_peer_names"`
	MaxChainDepth          *int            `json:"max_chain_depth"`
	CRLs                   []string        `json:"crls"`
}

type limboPeerName struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// limboKnownGap documents testcases whose PCL outcome differs from limbo.
type limboKnownGap struct {
	Reason string   `yaml:"reason"`
	Cases  []string `yaml:"cases"`
}

const (
	limboSuccess = "SUCCESS"
	limboFailure = "FAILURE"
)

func loadLimbo(t *testing.T) (limboSuite, map[string]string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(limboDir, "limbo.json"))
	if os.IsNotExist(err) && os.Getenv("PCL_REQUIRE_LIMBO") == "" {
		t.Skip("tests/limbo/limbo.json is missing; run tests/scripts/fetch-limbo.sh")
	}
	if err != nil {
		t.Fatalf("read limbo testcases: %v", err)
	}
	var suite limboSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("parse limbo testcases: %v", err)
	}
	if suite.Version != 1 {
		t.Fatalf("limbo schema version %d, want 1", suite.Version)
	}

	gaps := map[string]string{}
	data, err = os.ReadFile(filepath.Join(limboDir, "known-gaps.yaml"))
	if err != nil {
		t.Fatalf("read limbo known gaps: %v", err)
	}
	var listed []limboKnownGap
	if err := yaml.Unmarshal(data, &listed); err != nil {
		t.Fatalf("parse limbo known gaps: %v", err)
	}
	for _, gap := range listed {
		if gap.Reason == "" {
			t.Fatalf("known gap group %v has no reason", gap.Cases)
		}
		for _, id := range gap.Cases {
			if _, dup := gaps[id]; dup {
				t.Fatalf("known gap %s is listed twice", id)
			}
			gaps[id] = gap.Reason
		}
	}
	return suite, gaps
}

type limboOutcome struct {
	got         string
	failures    []string
	unsupported bool
}

func TestLimbo(t *testing.T) {
	if testing.Short() {
		t.Skip("x509-limbo runs every testcase")
	}
	suite, gaps := loadLimbo(t)

	// Testcases run on a worker pool; workers report errors instead of
	// calling t.Fatal, which must run on the test goroutine.
	root := t.TempDir()
	outcomes := make([]limboOutcome, len(suite.Testcases))
	errs := make([]error, len(suite.Testcases))
	work := make(chan int)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for index := range work {
				dir := filepath.Join(root, strconv.Itoa(index))
				outcomes[index], errs[index] = runLimbo(dir, suite.Testcases[index])
			}
		})
	}
	for index := range suite.Testcases {
		work <- index
	}
	close(work)
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	var conforming, gapped, unsupported int
	for index, tc := range suite.Testcases {
		seen[tc.ID] = true
		outcome := outcomes[index]
		_, known := gaps[tc.ID]
		switch {
		case outcome.unsupported && tc.ExpectedResult == limboSuccess:
			t.Errorf("%s: peer name does not match, yet limbo expects SUCCESS", tc.ID)
		case outcome.unsupported && known:
			t.Errorf("%s: depends on peer-name matching; remove it from known-gaps.yaml", tc.ID)
		case outcome.unsupported:
			unsupported++
		case outcome.got == tc.ExpectedResult && known:
			t.Errorf("%s: now %s as limbo expects; remove it from known-gaps.yaml", tc.ID, outcome.got)
		case outcome.got == tc.ExpectedResult:
			conforming++
		case known:
			gapped++
		default:
			t.Errorf("%s: %s, limbo expects %s; failed rules: %v", tc.ID, outcome.got, tc.ExpectedResult, outcome.failures)
		}
	}
	for id := range gaps {
		if !seen[id] {
			t.Errorf("known gap %s does not name a limbo testcase", id)
		}
	}
	t.Logf("x509-limbo: %d testcases conform, %d known gaps, %d unsupported (peer name)", conforming, gapped, unsupported)
}

// runLimbo lints one limbo testcase in dir and reports SUCCESS when no error
// rule fails for any certificate of the chain, together with the failed rules.
func runLimbo(dir string, tc limboCase) (limboOutcome, error) {
	matched, err := limboPeerNamesMatch(tc)
	if err != nil || !matched {
		return limboOutcome{unsupported: true}, err
	}

	cfg := linter.Config{
		PolicyPaths: []string{
			filepath.Join(limboDir, "path-policy.yaml"),
			filepath.Join("..", "policies", "RFC5280.yaml"),
		},
		CertPath:         filepath.Join(dir, "peer.pem"),
		TrustAnchorPaths: []string{filepath.Join(dir, "anchors")},
		ValidationTime:   limboValidationTime,
		PathRevocation:   pathpkg.RevocationIfPresent,
		OutputFmt:        output.FormatJSON,
	}
	files := map[string]string{cfg.CertPath: tc.PeerCertificate}
	for i, certificate := range tc.TrustedCerts {
		files[filepath.Join(dir, "anchors", fmt.Sprintf("anchor-%d.pem", i))] = certificate
	}
	for i, certificate := range tc.UntrustedIntermediates {
		path := filepath.Join(dir, fmt.Sprintf("intermediate-%d.pem", i))
		cfg.IssuerPaths = append(cfg.IssuerPaths, path)
		files[path] = certificate
	}
	if len(tc.CRLs) > 0 {
		cfg.CRLPath = filepath.Join(dir, "crls")
		for i, crl := range tc.CRLs {
			files[filepath.Join(cfg.CRLPath, fmt.Sprintf("crl-%d.pem", i))] = crl
		}
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return limboOutcome{}, err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return limboOutcome{}, err
		}
	}
	if tc.ValidationTime != nil {
		cfg.ValidationTime = *tc.ValidationTime
	}
	if len(tc.ExtendedKeyUsage) > 0 {
		cfg.ApplicationPurpose = tc.ExtendedKeyUsage[0]
	}
	if tc.MaxChainDepth != nil {
		cfg.MaximumPathLength = *tc.MaxChainDepth
		cfg.MaximumPathLengthConfigured = true
	}

	var out bytes.Buffer
	if err := linter.Run(cfg, &out); err != nil {
		return limboOutcome{got: limboFailure, failures: []string{"error: " + err.Error()}}, nil
	}
	var results []policy.Result
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		return limboOutcome{}, fmt.Errorf("%s: parse lint output: %w", tc.ID, err)
	}
	var failures []string
	for _, result := range results {
		for _, ruleResult := range result.Results {
			if ruleResult.Verdict == rule.VerdictFail && ruleResult.Severity == rule.SeverityError {
				failures = append(failures, result.CertType+":"+ruleResult.RuleID)
			}
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		return limboOutcome{got: limboFailure, failures: failures}, nil
	}
	return limboOutcome{got: limboSuccess}, nil
}

// limboPeerNamesMatch reports whether the subjectAltName of the peer
// certificate presents every expected peer name; like limbo, it does not fall
// back to the subject common name. PCL does not match peer names, so a
// testcase whose names do not match is outside what it can decide.
func limboPeerNamesMatch(tc limboCase) (bool, error) {
	names := tc.ExpectedPeerNames
	if tc.ExpectedPeerName != nil {
		names = append(names, *tc.ExpectedPeerName)
	}
	if len(names) == 0 {
		return true, nil
	}
	block, _ := pem.Decode([]byte(tc.PeerCertificate))
	if block == nil {
		return false, fmt.Errorf("%s: peer certificate is not PEM", tc.ID)
	}
	certificate, err := certparse.ParseCertificate(block.Bytes)
	if err != nil {
		// PCL rejects the certificate on its own.
		return true, nil
	}
	for _, name := range names {
		var matched bool
		switch name.Kind {
		case "DNS":
			// VerifyHostname falls back to the common name without dNSNames.
			matched = len(certificate.DNSNames) > 0 && certificate.VerifyHostname(name.Value) == nil
		case "IP":
			matched = certificate.VerifyHostname(name.Value) == nil
		case "RFC822":
			matched = slices.Contains(certificate.EmailAddresses, name.Value)
		default:
			return false, fmt.Errorf("%s: unknown peer name kind %q", tc.ID, name.Kind)
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}
