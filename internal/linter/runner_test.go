package linter

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
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

func TestLoadPoliciesRejectsUnknownOperator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown-operator.yaml")
	data := []byte(`
id: invalid-policy
rules:
  - id: typo
    target: certificate.version
    operator: doesNotExist
    severity: error
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadPolicies([]string{path}, operator.DefaultRegistry())
	if err == nil || !strings.Contains(err.Error(), `unknown operator "doesNotExist"`) {
		t.Fatalf("expected executable-policy validation error, got %v", err)
	}

	err = Run(Config{PolicyPaths: []string{path}}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `unknown operator "doesNotExist"`) {
		t.Fatalf("Run should reject the policy before loading inputs, got %v", err)
	}
}

func TestLoadPoliciesRejectsInvalidOperands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-operands.yaml")
	data := []byte(`
id: invalid-policy
rules:
  - id: invalid-operands
    target: certificate.version
    operator: gte
    operands: [not-a-number]
    severity: error
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadPolicies([]string{path}, operator.DefaultRegistry())
	if err == nil || !strings.Contains(err.Error(), `operator "gte"`) {
		t.Fatalf("expected operand validation error, got %v", err)
	}

	err = Run(Config{PolicyPaths: []string{path}}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `operator "gte"`) {
		t.Fatalf("Run should reject operands before loading inputs, got %v", err)
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

func TestLoadCRLs(t *testing.T) {
	// Test with empty path
	crls, err := loadCRLs("")
	if err != nil {
		t.Errorf("unexpected error for empty path: %v", err)
	}
	if crls != nil {
		t.Errorf("expected nil CRLs for empty path, got %d", len(crls))
	}
}

func TestLoadOCSPs(t *testing.T) {
	// Test with empty path
	ocsps, err := loadOCSPs("")
	if err != nil {
		t.Errorf("unexpected error for empty path: %v", err)
	}
	if ocsps != nil {
		t.Errorf("expected nil OCSPs for empty path, got %d", len(ocsps))
	}
}

func TestLoadIssuersIfProvided(t *testing.T) {
	// Test with no issuers
	issuers, cleanup, err := loadIssuersIfProvided(Config{}, false)
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
	_, cleanup, err := loadCertificates(Config{CertURLs: []string{"://invalid"}})
	if err == nil {
		t.Fatal("expected invalid URL error")
	}
	if cleanup == nil {
		t.Fatal("expected temporary-directory cleanup with error")
	}
	cleanup()
}

func TestLoadIssuers_returnsCleanupOnDownloadError(t *testing.T) {
	_, cleanup, err := loadIssuers(Config{IssuerURLs: []string{"://invalid"}})
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

func TestProcessCertificates_withCRLAndResolve(t *testing.T) {
	crlPath := filepath.Join("..", "..", "internal", "crl", "testdata", "test.crl")
	crls, err := loadCRLs(crlPath)
	if err != nil {
		t.Fatalf("loadCRLs: %v", err)
	}

	certDir := filepath.Join("..", "..", "tests", "certs")
	cfg := Config{
		CertPath: filepath.Join(certDir, "leaf.pem"),
		IssuerPaths: []string{
			filepath.Join(certDir, "intermediate.pem"),
			filepath.Join(certDir, "root.pem"),
		},
		CertTimeout:   5 * time.Second,
		OCSPTimeout:   5 * time.Second,
		MaxChainDepth: 10,
	}
	issuers, issuerCleanup, err := loadIssuersIfProvided(cfg, true)
	if err != nil {
		t.Fatalf("loadIssuersIfProvided: %v", err)
	}

	pol, err := policy.ParseFile(filepath.Join("..", "..", "tests", "policies", "crl-validity.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	reg := operator.DefaultRegistry()
	var buf bytes.Buffer
	if issuerCleanup != nil {
		defer issuerCleanup()
	}
	results, cleanup, err := processCertificates(cfg, []policy.Policy{pol}, reg, crls, nil, issuers, &buf)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("processCertificates: %v", err)
	}
	if results == nil {
		t.Fatal("expected results slice from processCertificates")
	}
}

func TestProcessCertificates_autoValidateExtendsChainFromIssuerPool(t *testing.T) {
	dir := t.TempDir()
	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate parent key: %v", err)
	}
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	parentStd := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Trusted Root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01},
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, parentStd, parentStd, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parentPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(parentPath, pemEncodeCert(parentDER), 0644); err != nil {
		t.Fatalf("write parent: %v", err)
	}

	interStd := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "No AIA Intermediate"},
		Issuer:                parentStd.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x02},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interStd, parentStd, &interKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	interPath := filepath.Join(dir, "inter.cer")
	if err := os.WriteFile(interPath, interDER, 0644); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}

	leafStd := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "subscriber.example"},
		Issuer:       interStd.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafStd, interStd, &interKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(leafPath, pemEncodeCert(leafDER), 0644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}

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

	reg := operator.DefaultRegistry()
	var buf bytes.Buffer
	results, cleanup, err := processCertificates(cfg, []policy.Policy{pol}, reg, nil, nil, nil, &buf)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("processCertificates: %v", err)
	}
	if results == nil {
		t.Fatal("expected results from auto-validate with issuer pool")
	}
}

func pemEncodeCert(der []byte) []byte {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}
