package linter

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
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
				CertTimeout:   10 * time.Second,
				OCSPTimeout:   5 * time.Second,
				OutputFmt:     "text",
				MaxChainDepth: 10,
			},
		},
		{
			name: "custom values preserved",
			input: Config{
				CertTimeout:   30 * time.Second,
				OCSPTimeout:   10 * time.Second,
				OutputFmt:     "json",
				MaxChainDepth: 5,
			},
			expected: Config{
				CertTimeout:   30 * time.Second,
				OCSPTimeout:   10 * time.Second,
				OutputFmt:     "json",
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

func TestConfigValidateRejectsInvalidInitialPolicyOID(t *testing.T) {
	err := Config{
		PolicyPaths: []string{"policy.yaml"},
		CertPath:    "leaf.pem",
		CertificatePolicyInputs: operator.CertificatePolicyInputs{
			Configured:       true,
			InitialPolicySet: []string{"1.03.6"},
		},
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "initial policy set") {
		t.Fatalf("expected invalid initial policy set error, got %v", err)
	}
}

func TestConfigValidateRejectsInvalidPathInputs(t *testing.T) {
	base := Config{PolicyPaths: []string{"policy.yaml"}, CertPath: "leaf.pem"}
	invalidMode := base
	invalidMode.PathRevocation = "sometimes"
	if err := invalidMode.Validate(); err == nil || !strings.Contains(err.Error(), "path-revocation") {
		t.Fatalf("invalid revocation mode error = %v", err)
	}
	invalidMaximum := base
	invalidMaximum.MaximumPathLengthConfigured = true
	invalidMaximum.MaximumPathLength = -1
	if err := invalidMaximum.Validate(); err == nil || !strings.Contains(err.Error(), "max-path-length") {
		t.Fatalf("invalid maximum path length error = %v", err)
	}
	maximumWithoutAnchor := base
	maximumWithoutAnchor.MaximumPathLengthConfigured = true
	maximumWithoutAnchor.MaximumPathLength = 1
	if err := maximumWithoutAnchor.Validate(); err == nil || !strings.Contains(err.Error(), "trust-anchor") {
		t.Fatalf("maximum path length without trust anchor error = %v", err)
	}
	peerNameWithoutAnchor := base
	peerNameWithoutAnchor.PeerNames = []string{"example.com"}
	if err := peerNameWithoutAnchor.Validate(); err == nil || !strings.Contains(err.Error(), "--peer-name requires --trust-anchor") {
		t.Fatalf("peer name without trust anchor error = %v", err)
	}
	invalidPeerName := base
	invalidPeerName.TrustAnchorPaths = []string{"root.pem"}
	invalidPeerName.PeerNames = []string{"*.example.com"}
	if err := invalidPeerName.Validate(); err == nil || !strings.Contains(err.Error(), "not a valid DNS name") {
		t.Fatalf("invalid peer name error = %v", err)
	}
	withoutCertificate := Config{
		PolicyPaths:      []string{"policy.yaml"},
		TrustAnchorPaths: []string{"root.pem"},
		CRLPath:          "list.crl",
	}
	if err := withoutCertificate.Validate(); err == nil || !strings.Contains(err.Error(), "trust-anchor") {
		t.Fatalf("trust anchor without certificate error = %v", err)
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
	return evaluator.Evaluate(buildSubjects(cfg, inputs, []policy.Policy{pol}, reg), reg)
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
			if _, _, err := buildCertificateChain(Config{}, tt.certs, nil, nil, &diagnostics); err != nil {
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

func TestRunProjectsExplicitPathValidation(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	intermediate := testpki.Issue(t, "Intermediate", root, testpki.CA(), testpki.Serial(2))
	leaf := testpki.Issue(t, "Leaf", intermediate, testpki.Serial(3))
	dir := t.TempDir()
	leafPath := writePEMCert(t, dir, "leaf.pem", leaf.DER)
	intermediatePath := writePEMCert(t, dir, "intermediate.pem", intermediate.DER)
	rootPath := writePEMCert(t, dir, "root.pem", root.DER)

	// Path findings follow the operator that decided the rule, not the
	// spelling of its target. Other operators explain themselves in one
	// finding named after the operator.
	tests := []struct {
		name             string
		rule             string
		wantPathFindings bool
	}{
		{
			name: "pathValid with qualified targets",
			rule: `    when:
      target: certificate.pathValidation
      operator: present
    target: certificate
    operator: pathValid
`,
			wantPathFindings: true,
		},
		{
			name: "pathValid with unqualified targets",
			rule: `    when:
      target: pathValidation
      operator: present
    target: subject
    operator: pathValid
`,
			wantPathFindings: true,
		},
		{
			name: "node operator on the path projection",
			rule: `    target: certificate.pathValidation.valid
    operator: eq
    operands: [true]
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyPath := filepath.Join(t.TempDir(), "path-policy.yaml")
			policyYAML := "id: path-validation\nversion: \"1\"\nrules:\n" +
				"  - id: certification-path-valid\n" + test.rule + "    severity: error\n"
			if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			err := Run(Config{
				PolicyPaths:      []string{policyPath},
				CertPath:         leafPath,
				IssuerPaths:      []string{intermediatePath},
				TrustAnchorPaths: []string{rootPath},
				ValidationTime:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
				PathRevocation:   "none",
				OutputFmt:        "json",
				Verbosity:        1,
			}, &output)
			if err != nil {
				t.Fatalf("Run: %v\n%s", err, output.String())
			}
			var results []policy.Result
			if err := json.Unmarshal(output.Bytes(), &results); err != nil {
				t.Fatal(err)
			}
			if len(results) != 3 || len(results[0].Results) != 1 {
				t.Fatalf("path validation results = %#v", results)
			}
			got := results[0].Results[0]
			pathFindings := len(got.Findings) > 1 && strings.HasPrefix(got.Findings[0].Code, "path.")
			explained := len(got.Findings) == 1 && got.Findings[0].Code == "eq"
			if got.Verdict != rule.VerdictPass || pathFindings != test.wantPathFindings ||
				explained == test.wantPathFindings {
				t.Fatalf("result = %#v, want pass with path findings %v", got, test.wantPathFindings)
			}
		})
	}
}

// When the best-ranked path fails validation, a lower-ranked valid path is
// used for the path decision and for the certificates that are linted.
func TestRunFallsBackToAValidAlternativePath(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.Serial(1))
	other := testpki.Issue(t, "Other CA", root, testpki.CA(), testpki.Serial(2))
	issuingKey := testpki.ECDSAKey(t)
	// The shorter path runs through a CA whose name constraints exclude the
	// leaf; the cross-certified CA under Other CA carries no constraints.
	constrained := testpki.IssueWithKey(t, "Issuing CA", issuingKey, root, testpki.CA(), testpki.Serial(3),
		testpki.Mutate(func(template *x509.Certificate) {
			template.PermittedDNSDomainsCritical = true
			template.PermittedDNSDomains = []string{"other.test"}
		}))
	crossCertified := testpki.IssueWithKey(t, "Issuing CA", issuingKey, other, testpki.CA(), testpki.Serial(4))
	leaf := testpki.Issue(t, "Leaf", constrained, testpki.Serial(5), testpki.Mutate(func(template *x509.Certificate) {
		template.DNSNames = []string{"www.example.test"}
	}))

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "path-policy.yaml")
	policyYAML := `id: path-validation
version: "1"
rules:
  - id: certification-path-valid
    when:
      target: certificate.pathValidation
      operator: present
    target: certificate
    operator: pathValid
    severity: error
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := Run(Config{
		PolicyPaths: []string{policyPath},
		CertPath:    writePEMCert(t, dir, "leaf.pem", leaf.DER),
		IssuerPaths: []string{
			writePEMCert(t, dir, "constrained.pem", constrained.DER),
			writePEMCert(t, dir, "cross.pem", crossCertified.DER),
			writePEMCert(t, dir, "other.pem", other.DER),
		},
		TrustAnchorPaths: []string{writePEMCert(t, dir, "root.pem", root.DER)},
		ValidationTime:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		PathRevocation:   "none",
		OutputFmt:        "json",
		Verbosity:        1,
		ShowMeta:         true,
	}, &buf)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, buf.String())
	}
	var out output.LintOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	results := out.Results
	var linted []string
	for _, result := range results {
		linted = append(linted, filepath.Base(result.CertPath))
	}
	if !slices.Equal(linted, []string{"leaf.pem", "cross.pem", "other.pem", "root.pem"}) {
		t.Fatalf("linted %v, want the alternative path leaf, cross, other, root", linted)
	}
	if got := results[0].Results[0]; got.Verdict != rule.VerdictPass {
		t.Fatalf("path decision = %#v, want pass", got)
	}

	// The run metadata names the alternative path as the evaluated chain.
	chain := out.Meta.Chain
	if chain == nil || !chain.Alternative || !chain.PathValidated || !chain.Anchored {
		t.Fatalf("meta chain = %#v, want a validated, anchored alternative path", chain)
	}
	var chainPaths []string
	for _, c := range chain.Certificates {
		chainPaths = append(chainPaths, filepath.Base(c.CertPath))
		if c.TrustAnchor != (filepath.Base(c.CertPath) == "root.pem") {
			t.Errorf("%s trust_anchor = %v", c.CertPath, c.TrustAnchor)
		}
	}
	if !slices.Equal(chainPaths, linted) {
		t.Errorf("meta chain %v, want the linted chain %v", chainPaths, linted)
	}
	if want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC); !out.Meta.ValidationTime.Equal(want) {
		t.Errorf("meta validation_time = %v, want %v", out.Meta.ValidationTime, want)
	}
	if len(out.Meta.Policies) != 1 || out.Meta.Policies[0] != (output.PolicyInfo{ID: "path-validation", Version: "1"}) {
		t.Errorf("meta policies = %#v", out.Meta.Policies)
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

func TestUnknownOutputFormatIsRejected(t *testing.T) {
	cfg := Config{
		PolicyPaths: []string{filepath.Join("..", "..", "tests", "policies", "basic.yaml")},
		CertPath:    filepath.Join("..", "..", "tests", "certs", "leaf.pem"),
		OutputFmt:   "xml",
	}
	var out bytes.Buffer
	for name, run := range map[string]func() error{
		"lint":    func() error { return Run(cfg, &out) },
		"inspect": func() error { return Inspect(cfg, InspectOptions{}, &out) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), `unknown output format "xml"`) {
			t.Errorf("%s: error = %v, want the unknown format", name, err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("output written before the format was rejected:\n%s", out.String())
	}
}

func TestInvalidOCSPRequestOptionsAreRejected(t *testing.T) {
	for _, cfg := range []Config{
		{OCSPHashAlgorithm: "md5"},
		{OCSPNonceValue: "not hex"},
		{OCSPNonceLength: 500},
	} {
		cfg.PolicyPaths = []string{filepath.Join("..", "..", "tests", "policies", "basic.yaml")}
		cfg.CertPath = filepath.Join("..", "..", "tests", "certs", "leaf.pem")
		if err := Run(cfg, io.Discard); err == nil {
			t.Errorf("Run(%+v) accepted invalid OCSP request options", cfg)
		}
	}
}

func TestRunFailOn(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	err := os.WriteFile(policyPath, []byte(`id: fail-on
version: "1"
rules:
  - id: version-is-two
    target: certificate.version
    operator: eq
    operands: [2]
    severity: warning
  - id: version-is-three
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error
  - id: ocsp-status-good
    target: certificate
    operator: notRevokedOCSP
    severity: warning
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Without an OCSP response ocsp-status-good is inconclusive; a gate counts
	// it like a failure so missing evidence never opens it.
	tests := []struct {
		failOn  string
		wantErr string
	}{
		{failOn: ""},
		{failOn: FailOnNone},
		{failOn: rule.SeverityError},
		{failOn: rule.SeverityWarning, wantErr: "2 failed or inconclusive rule(s) with severity warning or higher"},
		{failOn: rule.SeverityInfo, wantErr: "2 failed or inconclusive rule(s) with severity info or higher"},
		{failOn: "critical", wantErr: `unknown --fail-on severity "critical"`},
	}
	for _, tt := range tests {
		t.Run(tt.failOn, func(t *testing.T) {
			var out bytes.Buffer
			err := Run(Config{
				PolicyPaths: []string{policyPath},
				CertPath:    filepath.Join("..", "..", "tests", "certs", "leaf.pem"),
				OutputFmt:   output.FormatJSON,
				FailOn:      tt.failOn,
			}, &out)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Run() = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.HasPrefix(err.Error(), tt.wantErr)) {
				t.Fatalf("Run() = %v, want %q", err, tt.wantErr)
			}
			if tt.failOn != "critical" && !json.Valid(out.Bytes()) {
				t.Fatalf("results were not written before the run failed:\n%s", out.String())
			}
		})
	}
}

func TestRunReportsInputPathsWithoutFiles(t *testing.T) {
	err := Run(Config{
		PolicyPaths: []string{filepath.Join("..", "..", "tests", "policies", "basic.yaml")},
		CRLPath:     t.TempDir(),
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no CRL or OCSP response files found") {
		t.Fatalf("Run() = %v, want the empty input paths reported", err)
	}
}

func TestDiscoverSignerIssuersDownloadsCRLAndOCSPSignerIssuers(t *testing.T) {
	root := testpki.Issue(t, "Root", nil, testpki.CA())
	crlSigner := testpki.Issue(t, "CRL Signer", nil, testpki.CA(), testpki.Serial(2))
	responderIssuer := testpki.Issue(t, "Responder Issuer", nil, testpki.CA(), testpki.Serial(3))
	leaf := testpki.Issue(t, "Leaf", root, testpki.Serial(4),
		testpki.IssuingCertificateURLs(testpki.Serve(t, crlSigner.DER)))
	responder := testpki.Issue(t, "Responder", responderIssuer, testpki.Serial(5), testpki.OCSPSigning(),
		testpki.IssuingCertificateURLs(testpki.Serve(t, responderIssuer.DER)))

	list, err := crl.ParseCRL(crlSigner.RevocationList(t, &x509.RevocationList{}))
	if err != nil {
		t.Fatal(err)
	}
	response := testpki.OCSPResponse(t, root, responder, stdocsp.Response{
		Status:       stdocsp.Good,
		SerialNumber: big.NewInt(4),
		ThisUpdate:   testpki.NotBefore,
		NextUpdate:   testpki.NotAfter,
		Certificate:  responder.Std,
	})

	found := discoverSignerIssuers(Config{CertTimeout: time.Second, MaxChainDepth: 2}, lintInputs{
		chain: []*cert.Info{{Cert: leaf.Cert}, {Cert: root.Cert}},
		crls:  []*crl.Info{{CRL: list}},
		ocsps: []*ocsp.Info{{Response: response}},
	}, io.Discard)

	var names []string
	for _, info := range found {
		names = append(names, info.Cert.Subject.CommonName)
	}
	if !slices.Contains(names, "CRL Signer") || !slices.Contains(names, "Responder Issuer") {
		t.Fatalf("downloaded %v, want the CRL signer and the responder's issuer", names)
	}
}
