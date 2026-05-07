package linter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/ocsp"
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
			policies, err := loadPolicies(tt.paths)
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
