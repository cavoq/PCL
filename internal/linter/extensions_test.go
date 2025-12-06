package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cavoq/PCL/internal/policy"
)

func TestIsCritical(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 5, 29, 15}

	tests := []struct {
		name     string
		exts     []pkix.Extension
		expected bool
	}{
		{
			"critical extension",
			[]pkix.Extension{{Id: oid, Critical: true}},
			true,
		},
		{
			"non-critical extension",
			[]pkix.Extension{{Id: oid, Critical: false}},
			false,
		},
		{
			"extension not found",
			[]pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: true}},
			false,
		},
		{
			"empty extensions",
			[]pkix.Extension{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCritical(tt.exts, oid)
			if result != tt.expected {
				t.Errorf("isCritical() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckBitmaskFlags(t *testing.T) {
	checks := []UsageCheck[x509.KeyUsage]{
		{"digitalSignature", true, x509.KeyUsageDigitalSignature},
		{"keyCertSign", true, x509.KeyUsageCertSign},
		{"cRLSign", false, x509.KeyUsageCRLSign},
	}

	tests := []struct {
		name            string
		actual          x509.KeyUsage
		expectedMissing []string
		expectedPresent []string
	}{
		{
			"all required present",
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			nil,
			[]string{"digitalSignature", "keyCertSign"},
		},
		{
			"some missing",
			x509.KeyUsageDigitalSignature,
			[]string{"keyCertSign"},
			[]string{"digitalSignature"},
		},
		{
			"none present",
			0,
			[]string{"digitalSignature", "keyCertSign"},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missing, present := checkBitmaskFlags(tt.actual, checks)
			if len(missing) != len(tt.expectedMissing) {
				t.Errorf("missing = %v, want %v", missing, tt.expectedMissing)
			}
			if len(present) != len(tt.expectedPresent) {
				t.Errorf("present = %v, want %v", present, tt.expectedPresent)
			}
		})
	}
}

func TestCheckSliceFlags(t *testing.T) {
	checks := []UsageCheck[x509.ExtKeyUsage]{
		{"serverAuth", true, x509.ExtKeyUsageServerAuth},
		{"clientAuth", true, x509.ExtKeyUsageClientAuth},
	}

	tests := []struct {
		name            string
		actual          []x509.ExtKeyUsage
		expectedMissing []string
		expectedPresent []string
	}{
		{
			"all present",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			nil,
			[]string{"serverAuth", "clientAuth"},
		},
		{
			"some missing",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			[]string{"clientAuth"},
			[]string{"serverAuth"},
		},
		{
			"none present",
			[]x509.ExtKeyUsage{},
			[]string{"serverAuth", "clientAuth"},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missing, present := checkSliceFlags(tt.actual, checks)
			if len(missing) != len(tt.expectedMissing) {
				t.Errorf("missing = %v, want %v", missing, tt.expectedMissing)
			}
			if len(present) != len(tt.expectedPresent) {
				t.Errorf("present = %v, want %v", present, tt.expectedPresent)
			}
		})
	}
}

func TestLintKeyUsage_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature,
		},
		Policy: &policy.Policy{
			Extensions: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintKeyUsage(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Extensions is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintKeyUsage_NilKeyUsage(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature,
		},
		Policy: &policy.Policy{
			Extensions: &policy.Extensions{
				KeyUsage: nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintKeyUsage(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when KeyUsage is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintKeyUsage_AllPresent(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		Policy: &policy.Policy{
			Extensions: &policy.Extensions{
				KeyUsage: &policy.KeyUsageExtension{
					DigitalSignature: true,
					KeyCertSign:      true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintKeyUsage(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.key_usage" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding when all key usages present")
	}
}

func TestLintKeyUsage_Missing(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature,
		},
		Policy: &policy.Policy{
			Extensions: &policy.Extensions{
				KeyUsage: &policy.KeyUsageExtension{
					DigitalSignature: true,
					KeyCertSign:      true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintKeyUsage(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.key_usage" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding when key usages missing")
	}
}

func TestLintKeyUsage_Critical(t *testing.T) {
	tests := []struct {
		name           string
		critical       bool
		expectedStatus Status
	}{
		{"critical when required", true, StatusPass},
		{"not critical when required", false, StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Cert: &x509.Certificate{
					KeyUsage: x509.KeyUsageDigitalSignature,
					Extensions: []pkix.Extension{
						{Id: oidExtensionKeyUsage, Critical: tt.critical},
					},
				},
				Policy: &policy.Policy{
					Extensions: &policy.Extensions{
						KeyUsage: &policy.KeyUsageExtension{
							Critical:         true,
							DigitalSignature: true,
						},
					},
				},
				Result: &LintResult{Valid: true},
			}

			LintKeyUsage(job)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "crypto.key_usage.critical" && f.Status == tt.expectedStatus {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for critical check", tt.expectedStatus)
			}
		})
	}
}

func TestLintExtendedKeyUsage_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		Policy: &policy.Policy{
			Extensions: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintExtendedKeyUsage(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Extensions is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintExtendedKeyUsage_AllPresent(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
		Policy: &policy.Policy{
			Extensions: &policy.Extensions{
				ExtendedKeyUsage: &policy.ExtendedKeyUsageExtension{
					ServerAuth: true,
					ClientAuth: true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintExtendedKeyUsage(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.extended_key_usage" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding when all extended key usages present")
	}
}

func TestLintExtendedKeyUsage_Missing(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		Policy: &policy.Policy{
			Extensions: &policy.Extensions{
				ExtendedKeyUsage: &policy.ExtendedKeyUsageExtension{
					ServerAuth: true,
					ClientAuth: true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintExtendedKeyUsage(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "crypto.extended_key_usage" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding when extended key usages missing")
	}
}

func TestLintBasicConstraints_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			IsCA: true,
		},
		Policy: &policy.Policy{
			Extensions: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintBasicConstraints(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Extensions is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintBasicConstraints_IsCA(t *testing.T) {
	tests := []struct {
		name           string
		certIsCA       bool
		policyIsCA     bool
		expectedStatus Status
	}{
		{"CA cert matches CA policy", true, true, StatusPass},
		{"non-CA cert doesn't match CA policy", false, true, StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Cert: &x509.Certificate{
					IsCA: tt.certIsCA,
				},
				Policy: &policy.Policy{
					Extensions: &policy.Extensions{
						BasicConstraints: &policy.BasicConstraintsExtension{
							IsCA: tt.policyIsCA,
						},
					},
				},
				Result: &LintResult{Valid: true},
			}

			LintBasicConstraints(job)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "crypto.basic_constraints.is_ca" && f.Status == tt.expectedStatus {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for isCA check", tt.expectedStatus)
			}
		})
	}
}

func TestLintBasicConstraints_PathLen(t *testing.T) {
	pathLen := 1

	tests := []struct {
		name           string
		certPathLen    int
		maxPathLenZero bool
		expectedStatus Status
	}{
		{"matching path length", 1, false, StatusPass},
		{"different path length", 2, false, StatusFail},
		{"zero path length", 0, true, StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Cert: &x509.Certificate{
					MaxPathLen:     tt.certPathLen,
					MaxPathLenZero: tt.maxPathLenZero,
				},
				Policy: &policy.Policy{
					Extensions: &policy.Extensions{
						BasicConstraints: &policy.BasicConstraintsExtension{
							PathLenConstraint: &pathLen,
						},
					},
				},
				Result: &LintResult{Valid: true},
			}

			LintBasicConstraints(job)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "crypto.basic_constraints.path_len" && f.Status == tt.expectedStatus {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for pathLen check", tt.expectedStatus)
			}
		})
	}
}
