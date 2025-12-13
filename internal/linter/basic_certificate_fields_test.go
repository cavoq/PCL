package linter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/policy"
)

func TestLintBasicFields_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version:      3,
			SerialNumber: big.NewInt(12345),
		},
		Policy: &policy.Policy{
			BasicFields: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintBasicFields(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when rule is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintVersion_V3Certificate(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version: 3,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RequireV3: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintVersion(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.version" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for v3 certificate")
	}
}

func TestLintVersion_V1CertificateWithExtensions(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version: 1,
			Extensions: []pkix.Extension{
				{Id: []int{2, 5, 29, 15}},
			},
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RequireV3: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintVersion(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.version" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for v1 certificate with extensions")
	}
}

func TestLintVersion_V1CertificateNoExtensions(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version:    1,
			Extensions: nil,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RequireV3: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintVersion(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.version" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for v1 certificate when v3 is required")
	}
}

func TestLintSerialNumber_Missing(t *testing.T) {
	maxLen := 20
	job := &LintJob{
		Cert: &x509.Certificate{
			SerialNumber: nil,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SerialNumber: &policy.SerialNumberRule{
					RequirePositive: true,
					MaxLength:       &maxLen,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSerialNumber(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for missing serial number")
	}
}

func TestLintSerialNumberPositive_Positive(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	serialNumber := big.NewInt(12345)
	LintSerialNumberPositive(job, serialNumber)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number.positive" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for positive serial number")
	}
}

func TestLintSerialNumberPositive_Zero(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	serialNumber := big.NewInt(0)
	LintSerialNumberPositive(job, serialNumber)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number.positive" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for zero serial number")
	}
}

func TestLintSerialNumberPositive_Negative(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	serialNumber := big.NewInt(-12345)
	LintSerialNumberPositive(job, serialNumber)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number.positive" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for negative serial number")
	}
}

func TestLintSerialNumberLength_WithinLimit(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	serialNumber := big.NewInt(12345)
	LintSerialNumberLength(job, serialNumber, 20)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number.length" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for serial number within length limit")
	}
}

func TestLintSerialNumberLength_ExceedsLimit(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	serialNumber := new(big.Int)
	serialNumber.SetString("123456789012345678901234567890123456789012345678901234567890", 10)
	LintSerialNumberLength(job, serialNumber, 20)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number.length" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for serial number exceeding length limit")
	}
}

func TestLintSerialNumberLength_ExactlyAtLimit(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	bytes := make([]byte, 20)
	for i := range bytes {
		bytes[i] = 0xFF
	}
	serialNumber := new(big.Int).SetBytes(bytes)
	LintSerialNumberLength(job, serialNumber, 20)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.serial_number.length" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for serial number exactly at length limit")
	}
}

func TestLintUniqueIdentifiers_V3Certificate(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version: 3,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RejectUniqueIdentifiers: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintUniqueIdentifiers(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.unique_identifiers" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for v3 certificate without unique identifiers")
	}
}

func TestLintUniqueIdentifiers_V2Certificate(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version: 2,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RejectUniqueIdentifiers: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintUniqueIdentifiers(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.unique_identifiers" && f.Status == StatusWarn {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARN finding for v2 certificate")
	}
}

func TestLintUniqueIdentifiers_V1Certificate(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Version: 1,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RejectUniqueIdentifiers: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintUniqueIdentifiers(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.unique_identifiers" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for v1 certificate")
	}
}

func TestLintBasicFields_AllChecks(t *testing.T) {
	maxLen := 20
	job := &LintJob{
		Cert: &x509.Certificate{
			Version:      3,
			SerialNumber: big.NewInt(12345),
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				RequireV3: true,
				SerialNumber: &policy.SerialNumberRule{
					RequirePositive: true,
					MaxLength:       &maxLen,
				},
				RejectUniqueIdentifiers: true,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintBasicFields(job)

	expectedChecks := map[string]bool{
		"basic_fields.version":                false,
		"basic_fields.serial_number.positive": false,
		"basic_fields.serial_number.length":   false,
		"basic_fields.unique_identifiers":     false,
	}

	for _, f := range job.Result.Findings {
		if _, ok := expectedChecks[f.ID]; ok {
			if f.Status == StatusPass {
				expectedChecks[f.ID] = true
			}
		}
	}

	for check, passed := range expectedChecks {
		if !passed {
			t.Errorf("expected PASS for check %s", check)
		}
	}
}

func TestDaysCeil(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected int
	}{
		{"exactly 1 day", 24 * time.Hour, 1},
		{"exactly 2 days", 48 * time.Hour, 2},
		{"1 day and 1 hour", 25 * time.Hour, 2},
		{"23 hours", 23 * time.Hour, 1},
		{"1 hour", 1 * time.Hour, 1},
		{"0 hours", 0, 0},
		{"exactly 365 days", 365 * 24 * time.Hour, 365},
		{"365 days and 1 minute", 365*24*time.Hour + time.Minute, 366},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := daysCeil(tt.duration)
			if result != tt.expected {
				t.Errorf("daysCeil(%v) = %d, want %d", tt.duration, result, tt.expected)
			}
		})
	}
}

func TestLintValidity_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: time.Now().Add(-24 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Validity: nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when rule is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintValidity_ValidCertificate(t *testing.T) {
	now := time.Now().UTC()
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: now.Add(-24 * time.Hour),
			NotAfter:  now.Add(30 * 24 * time.Hour),
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Validity: &policy.ValidityRule{},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.validity" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for valid certificate")
	}
}

func TestLintValidity_ExpiredCertificate(t *testing.T) {
	now := time.Now().UTC()
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: now.Add(-60 * 24 * time.Hour),
			NotAfter:  now.Add(-30 * 24 * time.Hour),
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Validity: &policy.ValidityRule{},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.validity.notAfter" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for expired certificate")
	}
}

func TestLintValidity_NotYetValid(t *testing.T) {
	now := time.Now().UTC()
	job := &LintJob{
		Cert: &x509.Certificate{
			NotBefore: now.Add(24 * time.Hour),
			NotAfter:  now.Add(60 * 24 * time.Hour),
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Validity: &policy.ValidityRule{},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.validity.notBefore" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for not-yet-valid certificate")
	}
}

func TestLintValidity_MissingDates(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Validity: &policy.ValidityRule{},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintValidity(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.validity.dates" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for missing dates")
	}
}

func TestLintMinValidity(t *testing.T) {
	now := time.Now().UTC()
	minDays := 30

	tests := []struct {
		name           string
		notAfter       time.Time
		expectedStatus Status
	}{
		{"enough days remaining", now.Add(60 * 24 * time.Hour), StatusPass},
		{"not enough days remaining", now.Add(10 * 24 * time.Hour), StatusWarn},
		{"expired", now.Add(-1 * 24 * time.Hour), StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Result: &LintResult{Valid: true},
			}

			LintMinValidity(job, minDays, now, tt.notAfter)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "basic_fields.validity.min_validity" && f.Status == tt.expectedStatus {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for min validity check", tt.expectedStatus)
			}
		})
	}
}

func TestLintMaxValidity(t *testing.T) {
	now := time.Now().UTC()
	maxDays := 365

	tests := []struct {
		name           string
		notBefore      time.Time
		notAfter       time.Time
		expectedStatus Status
	}{
		{"within max", now, now.Add(100 * 24 * time.Hour), StatusPass},
		{"exactly max", now, now.Add(365 * 24 * time.Hour), StatusPass},
		{"exceeds max", now, now.Add(400 * 24 * time.Hour), StatusFail},
		{"invalid period", now.Add(24 * time.Hour), now, StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := &LintJob{
				Result: &LintResult{Valid: true},
			}

			LintMaxValidity(job, maxDays, tt.notBefore, tt.notAfter)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "basic_fields.validity.max_validity" {
					if f.Status == tt.expectedStatus {
						found = true
					}
					break
				}
			}
			if !found {
				t.Errorf("expected %s finding for max validity check", tt.expectedStatus)
			}
		})
	}
}

func TestLintNameRules_NilPolicy(t *testing.T) {
	job := &LintJob{
		Cert:   &x509.Certificate{},
		Policy: nil,
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Policy is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintNameRules_NilSubjectAndIssuer(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Subject: nil,
				Issuer:  nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when Subject and Issuer are nil, got %d", len(job.Result.Findings))
	}
}

func TestLintNoWildcards_NilRule(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	LintNoWildcards(job, nil, []string{"test.example.com"}, "subject")

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when rule is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintNoWildcards_NoWildcardsDisabled(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: false,
	}

	LintNoWildcards(job, rule, []string{"*.example.com"}, "subject")

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when NoWildcards is false, got %d", len(job.Result.Findings))
	}
}

func TestLintNoWildcards_NoWildcardsFound(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"test.example.com", "www.example.com"}, "subject")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding when no wildcards found")
	}
}

func TestLintNoWildcards_WildcardStar(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"*.example.com"}, "subject")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding when * wildcard found")
	}
}

func TestLintNoWildcards_WildcardQuestion(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"test?.example.com"}, "subject")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "subject.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding when ? wildcard found")
	}
}

func TestLintNoWildcards_IssuerField(t *testing.T) {
	job := &LintJob{
		Result: &LintResult{Valid: true},
	}

	rule := &policy.NameRule{
		NoWildcards: true,
	}

	LintNoWildcards(job, rule, []string{"*.example.com"}, "issuer")

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "issuer.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding with issuer prefix")
	}
}

func TestLintNameRules_SubjectWithWildcard(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "*.example.com",
			},
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Subject: &policy.NameRule{
					NoWildcards: true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.subject.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for subject with wildcard")
	}
}

func TestLintNameRules_IssuerWithWildcard(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "*.issuer.com",
			},
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Issuer: &policy.NameRule{
					NoWildcards: true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.issuer.no_wildcards" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for issuer with wildcard")
	}
}

func TestLintNameRules_EmptyNames(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			Subject: pkix.Name{},
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				Subject: &policy.NameRule{
					NoWildcards: true,
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintNameRules(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.subject.no_wildcards" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for empty subject names")
	}
}

func TestIsSignatureAlgorithmAllowed(t *testing.T) {
	tests := []struct {
		name     string
		actual   string
		allowed  []string
		expected bool
	}{
		{"exact match", "SHA256-RSA", []string{"SHA256-RSA", "SHA384-RSA"}, true},
		{"no match", "SHA256-RSA", []string{"SHA384-RSA", "SHA512-RSA"}, false},
		{"wildcard", "SHA256-RSA", []string{"*"}, true},
		{"empty allowed list", "SHA256-RSA", []string{}, false},
		{"single match", "ECDSA-SHA256", []string{"ECDSA-SHA256"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSignatureAlgorithmAllowed(tt.actual, tt.allowed)
			if result != tt.expected {
				t.Errorf("isSignatureAlgorithmAllowed(%q, %v) = %v, want %v",
					tt.actual, tt.allowed, result, tt.expected)
			}
		})
	}
}

func TestLintSignatureAlgorithm_NilBasicFields(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			BasicFields: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when BasicFields is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSignatureAlgorithm_NilSignatureAlgorithm(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SignatureAlgorithm: nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when SignatureAlgorithm is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSignatureAlgorithm_EmptyAllowedList(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when AllowedAlgorithms is empty, got %d", len(job.Result.Findings))
	}
}

func TestLintSignatureAlgorithm_Allowed(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{"SHA256-RSA", "SHA384-RSA"},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.signature_algorithm" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for allowed signature algorithm")
	}
}

func TestLintSignatureAlgorithm_NotAllowed(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{"SHA384-RSA", "SHA512-RSA"},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.signature_algorithm" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for disallowed signature algorithm")
	}
}

func TestLintSignatureAlgorithm_Wildcard(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SignatureAlgorithm: &policy.SignatureAlgorithmRule{
					AllowedAlgorithms: []string{"*"},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSignatureAlgorithm(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.signature_algorithm" && f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding when wildcard is allowed")
	}
}

func TestLintSignatureAlgorithm_AllAlgorithms(t *testing.T) {
	algorithms := []struct {
		algo       x509.SignatureAlgorithm
		stringName string
	}{
		{x509.SHA256WithRSA, "SHA256-RSA"},
		{x509.SHA384WithRSA, "SHA384-RSA"},
		{x509.SHA512WithRSA, "SHA512-RSA"},
		{x509.SHA256WithRSAPSS, "SHA256-RSAPSS"},
		{x509.SHA384WithRSAPSS, "SHA384-RSAPSS"},
		{x509.SHA512WithRSAPSS, "SHA512-RSAPSS"},
		{x509.ECDSAWithSHA256, "ECDSA-SHA256"},
		{x509.ECDSAWithSHA384, "ECDSA-SHA384"},
		{x509.ECDSAWithSHA512, "ECDSA-SHA512"},
		{x509.PureEd25519, "Ed25519"},
	}

	for _, alg := range algorithms {
		t.Run(alg.stringName, func(t *testing.T) {
			job := &LintJob{
				Cert: &x509.Certificate{
					SignatureAlgorithm: alg.algo,
				},
				Policy: &policy.Policy{
					BasicFields: &policy.BasicFieldsRule{
						SignatureAlgorithm: &policy.SignatureAlgorithmRule{
							AllowedAlgorithms: []string{alg.stringName},
						},
					},
				},
				Result: &LintResult{Valid: true},
			}

			LintSignatureAlgorithm(job)

			found := false
			for _, f := range job.Result.Findings {
				if f.ID == "basic_fields.signature_algorithm" && f.Status == StatusPass {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected PASS finding for %s algorithm", alg.stringName)
			}
		})
	}
}

func TestLintSubjectPublicKeyInfo_NilBasicFields(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			BasicFields: nil,
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when BasicFields is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSubjectPublicKeyInfo_NilRule(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: nil,
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when SubjectPublicKeyInfo is nil, got %d", len(job.Result.Findings))
	}
}

func TestLintSubjectPublicKeyInfo_EmptyAllowedAlgorithms(t *testing.T) {
	job := &LintJob{
		Cert: &x509.Certificate{},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	if len(job.Result.Findings) != 0 {
		t.Errorf("expected no findings when AllowedAlgorithms is empty, got %d", len(job.Result.Findings))
	}
}

func TestLintSubjectPublicKeyInfo_RSA_Allowed(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &rsaKey.PublicKey,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"RSA": {MinSize: 2048},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for allowed RSA key")
	}
}

func TestLintSubjectPublicKeyInfo_RSA_TooSmall(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &rsaKey.PublicKey,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"RSA": {MinSize: 2048},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for RSA key that is too small")
	}
}

func TestLintSubjectPublicKeyInfo_RSA_NotAllowed(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &rsaKey.PublicKey,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {MinSize: 256},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.ID == "basic_fields.subject_public_key_info" && f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for RSA key when only EC is allowed")
	}
}

func TestLintSubjectPublicKeyInfo_EC_Allowed(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &ecKey.PublicKey,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {
							MinSize:       256,
							AllowedCurves: []string{"P-256"},
						},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusPass {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PASS finding for allowed EC key")
	}
}

func TestLintSubjectPublicKeyInfo_EC_CurveNotAllowed(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &ecKey.PublicKey,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {
							MinSize:       256,
							AllowedCurves: []string{"P-384", "P-521"},
						},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for EC key with disallowed curve")
	}
}

func TestLintSubjectPublicKeyInfo_EC_TooSmall(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	job := &LintJob{
		Cert: &x509.Certificate{
			PublicKey: &ecKey.PublicKey,
		},
		Policy: &policy.Policy{
			BasicFields: &policy.BasicFieldsRule{
				SubjectPublicKeyInfo: &policy.SubjectPublicKeyInfoRule{
					AllowedAlgorithms: map[string]*policy.KeyAlgorithmRule{
						"EC": {
							MinSize:       384,
							AllowedCurves: []string{"P-256", "P-384"},
						},
					},
				},
			},
		},
		Result: &LintResult{Valid: true},
	}

	LintSubjectPublicKeyInfo(job)

	found := false
	for _, f := range job.Result.Findings {
		if f.Status == StatusFail {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FAIL finding for EC key that is too small")
	}
}
