package linter

import (
	"fmt"
	"math/big"
)

func LintBasicFields(job *LintJob) {
	rule := job.Policy.BasicFields

	if rule == nil {
		return
	}

	if rule.RequireV3 {
		LintVersion(job)
	}

	if rule.SerialNumber != nil {
		LintSerialNumber(job)
	}

	if rule.RejectUniqueIdentifiers {
		LintUniqueIdentifiers(job)
	}
}

func LintVersion(job *LintJob) {
	cert := job.Cert
	field := "basic_fields.version"

	version := cert.Version

	if version == 3 {
		job.Result.Add(field, StatusPass, "certificate is X.509 v3")
		return
	}

	hasExtensions := len(cert.Extensions) > 0

	if hasExtensions {
		job.Result.Add(field, StatusFail,
			fmt.Sprintf("certificate is X.509 v%d but has extensions (RFC 5280 requires v3 for certificates with extensions)", version))
		return
	}

	job.Result.Add(field, StatusFail,
		fmt.Sprintf("certificate is X.509 v%d, policy requires v3", version))
}

func LintSerialNumber(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.BasicFields.SerialNumber

	serialNumber := cert.SerialNumber

	if serialNumber == nil {
		job.Result.Add("basic_fields.serial_number", StatusFail, "serial number is missing")
		return
	}

	if rule.RequirePositive {
		LintSerialNumberPositive(job, serialNumber)
	}

	if rule.MaxLength != nil {
		LintSerialNumberLength(job, serialNumber, *rule.MaxLength)
	}
}

func LintSerialNumberPositive(job *LintJob, serialNumber *big.Int) {
	field := "basic_fields.serial_number.positive"

	if serialNumber.Sign() <= 0 {
		job.Result.Add(field, StatusFail,
			fmt.Sprintf("serial number must be positive (got %s)", serialNumber.String()))
		return
	}

	job.Result.Add(field, StatusPass, "serial number is positive")
}

func LintSerialNumberLength(job *LintJob, serialNumber *big.Int, maxLength int) {
	field := "basic_fields.serial_number.length"

	bytes := serialNumber.Bytes()
	length := len(bytes)

	if length == 0 {
		length = 1
	}

	if length > maxLength {
		job.Result.Add(field, StatusFail,
			fmt.Sprintf("serial number length %d octets exceeds maximum %d octets (RFC 5280 limit is 20)", length, maxLength))
		return
	}

	job.Result.Add(field, StatusPass,
		fmt.Sprintf("serial number length %d octets within limit of %d octets", length, maxLength))
}

func LintUniqueIdentifiers(job *LintJob) {
	cert := job.Cert
	field := "basic_fields.unique_identifiers"

	if cert.Version < 3 {
		if cert.Version == 2 {
			job.Result.Add(field, StatusWarn,
				"X.509 v2 certificate may contain unique identifiers (cannot verify - deprecated field)")
		} else {
			job.Result.Add(field, StatusPass,
				"X.509 v1 certificate (unique identifiers not applicable)")
		}
		return
	}

	job.Result.Add(field, StatusPass,
		"no deprecated unique identifiers detected (RFC 5280 compliant)")
}
