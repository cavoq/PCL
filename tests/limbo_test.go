package tests

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/linter"
	pathpkg "github.com/cavoq/PCL/internal/path"
)

// x509-limbo runs through the lint entry point with the shared path policy
// and the shipped RFC 5280 profile. tests/limbo/limbo.json is not committed;
// fetch it with `make limbo-fetch`. PCL_REQUIRE_LIMBO=1 turns a missing file
// into a failure.

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

const (
	limboSuccess = "SUCCESS"
	limboFailure = "FAILURE"
)

func loadLimbo(t *testing.T) limboSuite {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(limboDir, "limbo.json"))
	if os.IsNotExist(err) && os.Getenv("PCL_REQUIRE_LIMBO") == "" {
		t.Skip("tests/limbo/limbo.json is missing; run make limbo-fetch")
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

	return suite
}

type limboOutcome struct {
	got      string
	failures []string
}

func TestLimbo(t *testing.T) {
	if testing.Short() {
		t.Skip("x509-limbo runs every testcase")
	}
	suite := loadLimbo(t)

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

	conformance := loadConformance(t, "x509-limbo", filepath.Join(limboDir, "known-gaps.yaml"))
	for index, tc := range suite.Testcases {
		conformance.check(t, tc.ID, outcomes[index].got, tc.ExpectedResult, outcomes[index].failures)
	}
	conformance.finish(t)
}

// runLimbo lints one limbo testcase in dir and reports SUCCESS when no error
// rule fails for any certificate of the chain, together with the failed rules.
func runLimbo(dir string, tc limboCase) (limboOutcome, error) {
	peerNames, err := limboPeerNames(tc)
	if err != nil {
		return limboOutcome{}, err
	}
	cfg := linter.Config{
		PolicyPaths: []string{
			pathPolicy,
			filepath.Join("..", "policies", "RFC5280.yaml"),
		},
		CertPath:         filepath.Join(dir, "peer.pem"),
		TrustAnchorPaths: []string{filepath.Join(dir, "anchors")},
		ValidationTime:   limboValidationTime,
		PeerNames:        peerNames,
		PathRevocation:   pathpkg.RevocationIfPresent,
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

	valid, failures, err := lintAccepts(cfg)
	if err != nil {
		return limboOutcome{}, fmt.Errorf("%s: %w", tc.ID, err)
	}
	if valid {
		return limboOutcome{got: limboSuccess}, nil
	}
	return limboOutcome{got: limboFailure, failures: failures}, nil
}

// limboPeerNames returns the testcase's expected peer names. PCL infers a
// name's kind from its syntax, so each must be inferred as the kind limbo
// states.
func limboPeerNames(tc limboCase) ([]string, error) {
	names := tc.ExpectedPeerNames
	if tc.ExpectedPeerName != nil {
		names = append(names, *tc.ExpectedPeerName)
	}
	values := make([]string, 0, len(names))
	for _, name := range names {
		parsed, err := cert.ParsePeerName(name.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tc.ID, err)
		}
		if string(parsed.Kind) != name.Kind {
			return nil, fmt.Errorf("%s: peer name %q is a %s name, limbo states %s", tc.ID, name.Value, parsed.Kind, name.Kind)
		}
		values = append(values, name.Value)
	}
	return values, nil
}
