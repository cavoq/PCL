package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

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
		"basic_fields.version":              false,
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
