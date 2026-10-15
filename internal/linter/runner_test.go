package linter

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/evaluator"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/cavoq/PCL/internal/testpki"
)

func TestApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    Config
		expected Config
	}{
		{
			name:  "empty config gets defaults",
			input: Config{},
			expected: Config{
				CertTimeout: 10 * time.Second,
				OCSPTimeout: 5 * time.Second,
				OutputFmt:   "text",
			},
		},
		{
			name: "custom timeouts preserved",
			input: Config{
				CertTimeout: 30 * time.Second,
				OCSPTimeout: 10 * time.Second,
				OutputFmt:   "json",
			},
			expected: Config{
				CertTimeout: 30 * time.Second,
				OCSPTimeout: 10 * time.Second,
				OutputFmt:   "json",
			},
		},
		{
			name: "auto-validate sets max chain depth",
			input: Config{
				AutoValidate: true,
			},
			expected: Config{
				CertTimeout:   10 * time.Second,
				OCSPTimeout:   5 * time.Second,
				OutputFmt:     "text",
				AutoValidate:  true,
				MaxChainDepth: 10,
			},
		},
		{
			name: "auto-validate preserves custom max chain depth",
			input: Config{
				AutoValidate:  true,
				MaxChainDepth: 5,
			},
			expected: Config{
				CertTimeout:   10 * time.Second,
				OCSPTimeout:   5 * time.Second,
				OutputFmt:     "text",
				AutoValidate:  true,
				MaxChainDepth: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.input
			applyDefaults(&cfg)

			if cfg.CertTimeout != tt.expected.CertTimeout {
				t.Errorf("CertTimeout: got %v, want %v", cfg.CertTimeout, tt.expected.CertTimeout)
			}
			if cfg.OCSPTimeout != tt.expected.OCSPTimeout {
				t.Errorf("OCSPTimeout: got %v, want %v", cfg.OCSPTimeout, tt.expected.OCSPTimeout)
			}
			if cfg.OutputFmt != tt.expected.OutputFmt {
				t.Errorf("OutputFmt: got %v, want %v", cfg.OutputFmt, tt.expected.OutputFmt)
			}
			if cfg.MaxChainDepth != tt.expected.MaxChainDepth {
				t.Errorf("MaxChainDepth: got %v, want %v", cfg.MaxChainDepth, tt.expected.MaxChainDepth)
			}
		})
	}
}

func TestIsDirectory(t *testing.T) {
	// Create temp directory and file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{
			name: "directory returns true",
			path: tmpDir,
			want: true,
		},
		{
			name: "file returns false",
			path: tmpFile,
			want: false,
		},
		{
			name:    "non-existent returns error",
			path:    filepath.Join(tmpDir, "nonexistent"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isDirectory(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildNonceOptions(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected *ocsp.NonceOptions
	}{
		{
			name:   "default nonce options",
			config: Config{},
			expected: &ocsp.NonceOptions{
				Disabled: false,
			},
		},
		{
			name: "custom nonce length",
			config: Config{
				OCSPNonceLength: 32,
			},
			expected: &ocsp.NonceOptions{
				Length:   32,
				Disabled: false,
			},
		},
		{
			name: "nonce disabled",
			config: Config{
				NoOCSPNonce: true,
			},
			expected: &ocsp.NonceOptions{
				Disabled: true,
			},
		},
		{
			name: "custom hash algorithm",
			config: Config{
				OCSPHashAlgorithm: "SHA384",
			},
			expected: &ocsp.NonceOptions{
				Hash:     "SHA384",
				Disabled: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNonceOptions(tt.config)

			if got.Length != tt.expected.Length {
				t.Errorf("Length: got %v, want %v", got.Length, tt.expected.Length)
			}
			if got.Disabled != tt.expected.Disabled {
				t.Errorf("Disabled: got %v, want %v", got.Disabled, tt.expected.Disabled)
			}
			if got.Hash != tt.expected.Hash {
				t.Errorf("Hash: got %v, want %v", got.Hash, tt.expected.Hash)
			}
		})
	}
}

func TestLoadPolicies(t *testing.T) {
	// Create temp directory with policy files
	tmpDir := t.TempDir()

	// Create a simple policy file
	policyContent := `
id: test-policy
version: "1.0"
rules:
  - id: test-rule
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error
`
	policyFile := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create another policy file
	policyContent2 := `
id: test-policy-2
version: "1.0"
rules:
  - id: test-rule-2
    target: certificate.version
    operator: eq
    operands: [3]
    severity: warning
`
	policyFile2 := filepath.Join(tmpDir, "test2.yaml")
	if err := os.WriteFile(policyFile2, []byte(policyContent2), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		paths   []string
		wantLen int
		wantErr bool
	}{
		{
			name:    "single file",
			paths:   []string{policyFile},
			wantLen: 1,
		},
		{
			name:    "directory",
			paths:   []string{tmpDir},
			wantLen: 2, // Both .yaml files
		},
		{
			name:    "multiple files",
			paths:   []string{policyFile, policyFile2},
			wantLen: 2,
		},
		{
			name:    "non-existent file",
			paths:   []string{filepath.Join(tmpDir, "nonexistent.yaml")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := loadPolicies(tt.paths, operator.DefaultRegistry())
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(policies) != tt.wantLen {
				t.Errorf("got %d policies, want %d", len(policies), tt.wantLen)
			}
		})
	}
}

func TestLoadPoliciesRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want string
	}{
		{"unknown operator", "operator: doesNotExist", `unknown operator "doesNotExist"`},
		{"invalid operands", "operator: gte\n    operands: [not-a-number]", `operator "gte"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.yaml")
			data := "id: invalid-policy\nrules:\n  - id: invalid\n    target: certificate.version\n    " +
				tt.rule + "\n    severity: error\n"
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := loadPolicies([]string{path}, operator.DefaultRegistry())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected executable-policy validation error, got %v", err)
			}
			err = Run(Config{PolicyPaths: []string{path}, CertPath: filepath.Join(t.TempDir(), "missing.pem")}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run should reject the policy before loading inputs, got %v", err)
			}
		})
	}
}

func TestLoadPoliciesRejectsEmptyInputs(t *testing.T) {
	registry := operator.DefaultRegistry()
	if _, err := loadPolicies(nil, registry); err == nil {
		t.Fatal("expected missing policy path error")
	}
	if _, err := loadPolicies([]string{t.TempDir()}, registry); err == nil {
		t.Fatal("expected empty policy directory error")
	}

	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, []byte("id: empty\nrules: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicies([]string{path}, registry); err == nil || !strings.Contains(err.Error(), "contains no rules") {
		t.Fatalf("expected zero-rule policy error, got %v", err)
	}
}

func TestRunRejectsNoApplicablePolicy(t *testing.T) {
	cfg := Config{
		PolicyPaths: []string{filepath.Join("..", "..", "tests", "policies", "crl-validity.yaml")},
		CertPath:    filepath.Join("..", "..", "tests", "certs", "root.pem"),
	}

	err := Run(cfg, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no loaded policy applies") {
		t.Fatalf("expected no-applicable-policy error, got %v", err)
	}
}

func TestRunRejectsIssuerOnlyInputBeforeLoading(t *testing.T) {
	cfg := Config{
		PolicyPaths: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		IssuerPaths: []string{filepath.Join("..", "..", "tests", "certs", "root.pem")},
	}

	err := Run(cfg, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no certificates, CRLs, or OCSP responses provided") {
		t.Fatalf("expected missing lint input error, got %v", err)
	}
}

func TestConfigValidateRequiresPolicy(t *testing.T) {
	err := Config{CertPath: "leaf.pem"}.Validate()
	if err == nil || !strings.Contains(err.Error(), "policy path is required") {
		t.Fatalf("expected missing policy error, got %v", err)
	}
}

func TestLoadCRLs(t *testing.T) {
	// Test with empty path
	crls, err := loadCRLs("", nil)
	if err != nil {
		t.Errorf("unexpected error for empty path: %v", err)
	}
	if crls != nil {
		t.Errorf("expected nil CRLs for empty path, got %d", len(crls))
	}
}

func TestLoadOCSPs(t *testing.T) {
	// Test with empty path
	ocsps, err := loadOCSPs("", nil)
	if err != nil {
		t.Errorf("unexpected error for empty path: %v", err)
	}
	if ocsps != nil {
		t.Errorf("expected nil OCSPs for empty path, got %d", len(ocsps))
	}
}

func TestLoadIssuersIfProvided(t *testing.T) {
	// Test with no issuers
	issuers, cleanup, err := loadIssuersIfProvided(Config{}, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if issuers != nil {
		t.Errorf("expected nil issuers, got %d", len(issuers))
	}
	if cleanup != nil {
		t.Errorf("expected nil cleanup")
	}
}

func TestApplyDefaults_normalizesLegacyIssuerPath(t *testing.T) {
	cfg := Config{
		IssuerPath:  "legacy.pem",
		IssuerPaths: []string{"other.pem"},
	}
	applyDefaults(&cfg)

	want := []string{"legacy.pem", "other.pem"}
	if len(cfg.IssuerPaths) != len(want) {
		t.Fatalf("IssuerPaths = %v, want %v", cfg.IssuerPaths, want)
	}
	for i := range want {
		if cfg.IssuerPaths[i] != want[i] {
			t.Fatalf("IssuerPaths = %v, want %v", cfg.IssuerPaths, want)
		}
	}
}

func TestCleanupStack_closesInReverseOrderOnce(t *testing.T) {
	var got []int
	var cleanups cleanupStack
	cleanups.Add(func() { got = append(got, 1) })
	cleanups.Add(nil)
	cleanups.Add(func() { got = append(got, 2) })

	cleanups.Close()
	cleanups.Close()

	if len(got) != 2 || got[0] != 2 || got[1] != 1 {
		t.Fatalf("cleanup order = %v, want [2 1]", got)
	}
}

func TestLoadCertificates_returnsCleanupOnDownloadError(t *testing.T) {
	_, cleanup, err := loadCertificates(Config{CertURLs: []string{"://invalid"}}, nil)
	if err == nil {
		t.Fatal("expected invalid URL error")
	}
	if cleanup == nil {
		t.Fatal("expected temporary-directory cleanup with error")
	}
	cleanup()
}

func TestLoadIssuers_returnsCleanupOnDownloadError(t *testing.T) {
	_, cleanup, err := loadIssuers(Config{IssuerURLs: []string{"://invalid"}}, nil)
	if err == nil {
		t.Fatal("expected invalid URL error")
	}
	if cleanup == nil {
		t.Fatal("expected temporary-directory cleanup with error")
	}
	cleanup()
}

func TestRun_certificateLoadFailureIsFatal(t *testing.T) {
	cfg := Config{
		PolicyPaths: []string{filepath.Join("..", "..", "tests", "policies", "basic.yaml")},
		CertPath:    filepath.Join(t.TempDir(), "missing.pem"),
	}

	err := Run(cfg, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected certificate load error")
	}
	if !strings.Contains(err.Error(), "failed to load certificates") {
		t.Fatalf("Run error = %q, want certificate load context", err)
	}
}

func TestCrlResolveTimeout_prefersCertTimeout(t *testing.T) {
	cfg := Config{
		CertTimeout: 30 * time.Second,
		OCSPTimeout: 5 * time.Second,
	}
	if got := crlResolveTimeout(cfg); got != 30*time.Second {
		t.Fatalf("crlResolveTimeout() = %v, want 30s", got)
	}
}

func TestCrlResolveTimeout_fallsBackToOCSPTimeout(t *testing.T) {
	cfg := Config{OCSPTimeout: 7 * time.Second}
	if got := crlResolveTimeout(cfg); got != 7*time.Second {
		t.Fatalf("crlResolveTimeout() = %v, want 7s", got)
	}
}

func TestCrlResolveMaxDepth_usesConfig(t *testing.T) {
	cfg := Config{MaxChainDepth: 3}
	if got := crlResolveMaxDepth(cfg); got != 3 {
		t.Fatalf("crlResolveMaxDepth() = %d, want 3", got)
	}
}

func TestCrlResolveMaxDepth_default(t *testing.T) {
	cfg := Config{}
	if got := crlResolveMaxDepth(cfg); got != 10 {
		t.Fatalf("crlResolveMaxDepth() = %d, want 10", got)
	}
}

func TestCRLRevocationRequested(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{name: "not requested"},
		{name: "explicit CRL", cfg: Config{CRLPath: "list.crl"}, want: true},
		{name: "automatic CRL", cfg: Config{AutoValidate: true}, want: true},
		{
			name: "automatic CRL disabled",
			cfg:  Config{AutoValidate: true, NoAutoCRL: true},
		},
		{
			name: "explicit CRL survives automatic disable",
			cfg: Config{
				CRLPath:      "list.crl",
				AutoValidate: true,
				NoAutoCRL:    true,
			},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := crlRevocationRequested(test.cfg); got != test.want {
				t.Fatalf("crlRevocationRequested() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRunAutoCRLProjectsRevokedStatus(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := testpki.Issue(t, "Auto CRL Root", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x01, 0x02, 0x03}),
		testpki.Validity(now.Add(-24*time.Hour), now.Add(24*time.Hour)))
	leafSerial := big.NewInt(2)
	crlDER := root.RevocationList(t, &x509.RevocationList{
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   leafSerial,
			RevocationTime: now.Add(-30 * time.Minute),
		}},
	})
	crlURL, hits := testpki.ServeCounted(t, crlDER)

	leaf := testpki.Issue(t, "revoked.example", root, testpki.Serial(leafSerial.Int64()),
		testpki.Validity(now.Add(-time.Hour), now.Add(time.Hour)),
		testpki.Mutate(func(template *x509.Certificate) {
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.BasicConstraintsValid = true
			template.CRLDistributionPoints = []string{crlURL}
		}))

	dir := t.TempDir()
	rootPath := writePEMCert(t, dir, "root.pem", root.DER)
	leafPath := writePEMCert(t, dir, "leaf.pem", leaf.DER)
	policyPath := filepath.Join(dir, "revocation.yaml")
	policyYAML := []byte(`id: auto-crl
version: 1.0
rules:
  - id: status-known
    target: certificate.revocation.status
    operator: neq
    operands: [unknown]
    severity: error
  - id: not-revoked
    target: certificate.revocation.status
    operator: neq
    operands: [revoked]
    severity: error
`)
	if err := os.WriteFile(policyPath, policyYAML, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var outputBuffer bytes.Buffer
	err := Run(Config{
		PolicyPaths:  []string{policyPath},
		CertPath:     leafPath,
		IssuerPaths:  []string{rootPath},
		AutoValidate: true,
		NoAutoChain:  true,
		NoAutoOCSP:   true,
		CertTimeout:  time.Second,
		OutputFmt:    "json",
		Verbosity:    2,
		ShowMeta:     true,
	}, &outputBuffer)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("CRL endpoint hits = %d, want 1", hits.Load())
	}

	var lintOutput output.LintOutput
	if err := json.Unmarshal(outputBuffer.Bytes(), &lintOutput); err != nil {
		t.Fatalf("decode output: %v\n%s", err, outputBuffer.String())
	}
	for _, result := range lintOutput.Results {
		if result.CertType != "leaf" {
			continue
		}
		verdicts := make(map[string]string, len(result.Results))
		for _, result := range result.Results {
			verdicts[result.RuleID] = result.Verdict
		}
		if verdicts["status-known"] != rule.VerdictPass ||
			verdicts["not-revoked"] != rule.VerdictFail {
			t.Fatalf("leaf revocation verdicts = %#v", verdicts)
		}
		return
	}
	t.Fatal("leaf result is missing")
}

func TestAcquireInputs_withCRLAndResolve(t *testing.T) {
	certDir := filepath.Join("..", "..", "tests", "certs")
	cfg := Config{
		CertPath: filepath.Join(certDir, "leaf.pem"),
		IssuerPaths: []string{
			filepath.Join(certDir, "intermediate.pem"),
			filepath.Join(certDir, "root.pem"),
		},
		CRLPath:       filepath.Join("..", "..", "internal", "crl", "testdata", "test.crl"),
		CertTimeout:   5 * time.Second,
		OCSPTimeout:   5 * time.Second,
		MaxChainDepth: 10,
	}

	pol, err := policy.ParseFile(filepath.Join("..", "..", "tests", "policies", "crl-validity.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if results := lintForTest(t, cfg, pol); results == nil {
		t.Fatal("expected results for the CRL input")
	}
}

// lintForTest acquires inputs and evaluates pol the way Run does.
func lintForTest(t *testing.T, cfg Config, pol policy.Policy) []policy.Result {
	t.Helper()
	var cleanups cleanupStack
	t.Cleanup(cleanups.Close)
	var buf bytes.Buffer
	inputs, err := acquireInputs(cfg, &buf, &cleanups)
	if err != nil {
		t.Fatalf("acquireInputs: %v", err)
	}
	reg := operator.DefaultRegistry()
	return evaluator.Evaluate(buildSubjects(cfg, inputs, []policy.Policy{pol}, reg, &buf), reg)
}

func TestAcquireInputs_autoValidateExtendsChainFromIssuerPool(t *testing.T) {
	dir := t.TempDir()
	parent := testpki.Issue(t, "Trusted Root", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x01}))
	intermediate := testpki.Issue(t, "No AIA Intermediate", parent, testpki.CA(), testpki.Serial(2),
		testpki.SubjectKeyID([]byte{0x02}))
	leaf := testpki.Issue(t, "subscriber.example", intermediate, testpki.Serial(3))
	parentPath := writePEMCert(t, dir, "root.pem", parent.DER)
	interPath := filepath.Join(dir, "inter.cer")
	if err := os.WriteFile(interPath, intermediate.DER, 0o600); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}
	leafPath := writePEMCert(t, dir, "leaf.pem", leaf.DER)

	cfg := Config{
		CertPath:      leafPath,
		IssuerPaths:   []string{interPath, parentPath},
		AutoValidate:  true,
		NoAutoCRL:     true,
		NoAutoOCSP:    true,
		CertTimeout:   5 * time.Second,
		MaxChainDepth: 5,
	}
	applyDefaults(&cfg)

	pol, err := policy.ParseFile(filepath.Join("..", "..", "tests", "policies", "basic.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	if results := lintForTest(t, cfg, pol); results == nil {
		t.Fatal("expected results from auto-validate with issuer pool")
	}
}

func writePEMCert(t *testing.T, dir, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, testpki.PEM("CERTIFICATE", der), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestBuildCertificateChain_reportsCertificatesLeftOut(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	leaf := testpki.Issue(t, "Leaf", root, testpki.Serial(2))
	other := testpki.Issue(t, "Other Root", nil, testpki.CA(), testpki.Serial(3))

	tests := []struct {
		name  string
		certs []*cert.Info
		warn  []string
	}{
		{
			name:  "unrelated certificate",
			certs: []*cert.Info{{Cert: leaf.Cert, FilePath: "leaf.pem"}, {Cert: other.Cert, FilePath: "other.pem"}},
			warn:  []string{"other.pem"},
		},
		{
			// The same certificate in a bundle and its own file is linted once.
			name: "same certificate in two files",
			certs: []*cert.Info{
				{Cert: leaf.Cert, FilePath: "bundle.pem"},
				{Cert: root.Cert, FilePath: "bundle.pem"},
				{Cert: leaf.Cert, FilePath: "leaf.pem"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diagnostics bytes.Buffer
			if _, _, err := buildCertificateChain(Config{}, tt.certs, nil, &diagnostics); err != nil {
				t.Fatal(err)
			}
			warnings := strings.Count(diagnostics.String(), "is not part of the evaluated certificate chain")
			if warnings != len(tt.warn) {
				t.Fatalf("warnings:\n%s\nwant %d, for %v", diagnostics.String(), len(tt.warn), tt.warn)
			}
			for _, path := range tt.warn {
				if !strings.Contains(diagnostics.String(), path) {
					t.Errorf("no warning for %s:\n%s", path, diagnostics.String())
				}
			}
		})
	}
}

// Finding the signer of a CRL or the issuer of a delegated OCSP responder may
// download certificates from CA Issuers URLs, but only when chain climbing is
// enabled. Without --auto-validate a run stays offline.
func TestRun_downloadsSignerIssuersOnlyWhenClimbing(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	unsupplied := testpki.Issue(t, "Unsupplied CA", nil, testpki.CA(), testpki.Serial(2))
	url, hits := testpki.ServeCounted(t, unsupplied.DER)

	leaf := testpki.Issue(t, "Leaf", root, testpki.Serial(3), testpki.IssuingCertificateURLs(url))
	responder := testpki.Issue(t, "Responder", unsupplied, testpki.Serial(4),
		testpki.OCSPSigning(), testpki.IssuingCertificateURLs(url))
	response := testpki.OCSPResponse(t, root, responder, stdocsp.Response{
		Status:       stdocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   testpki.NotBefore,
		NextUpdate:   testpki.NotAfter,
		Certificate:  responder.Std,
	})

	dir := t.TempDir()
	files := map[string][]byte{
		"leaf.pem":       testpki.PEM("CERTIFICATE", leaf.DER),
		"root.pem":       testpki.PEM("CERTIFICATE", root.DER),
		"unsupplied.crl": unsupplied.RevocationList(t, &x509.RevocationList{}),
		"responder.ocsp": response.Raw,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pol, err := policy.ParseFile(filepath.Join("..", "..", "tests", "policies", "crl-validity.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		auto      bool
		noChain   bool
		wantFetch bool
	}{
		{name: "without auto-validate"},
		{name: "auto-validate without chain climbing", auto: true, noChain: true},
		{name: "auto-validate", auto: true, wantFetch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits.Store(0)
			cfg := Config{
				CertPath:       filepath.Join(dir, "leaf.pem"),
				IssuerPaths:    []string{filepath.Join(dir, "root.pem")},
				CRLPath:        filepath.Join(dir, "unsupplied.crl"),
				OCSPPath:       filepath.Join(dir, "responder.ocsp"),
				AutoValidate:   tt.auto,
				NoAutoChain:    tt.noChain,
				NoAutoCRL:      true,
				NoAutoOCSP:     true,
				ValidationTime: testpki.NotBefore.AddDate(0, 1, 0),
			}
			applyDefaults(&cfg)
			lintForTest(t, cfg, pol)
			if fetched := hits.Load() > 0; fetched != tt.wantFetch {
				t.Fatalf("CA Issuers requests = %d, want fetching %v", hits.Load(), tt.wantFetch)
			}
		})
	}
}
