package linter

import (
	"crypto/dsa" // #nosec G505 - deprecated but needed for legacy certificate validation
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/utils"
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

func LintValidity(job *LintJob) {
	cert := job.Cert
	if job.Policy.BasicFields == nil || job.Policy.BasicFields.Validity == nil {
		return
	}
	rule := job.Policy.BasicFields.Validity

	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		job.Result.Add("basic_fields.validity.dates", StatusFail, "notBefore/notAfter missing in certificate")
		return
	}

	now := time.Now().UTC()
	notBefore := cert.NotBefore.UTC()
	notAfter := cert.NotAfter.UTC()

	if now.Before(notBefore) {
		job.Result.Add("basic_fields.validity.notBefore", StatusFail, "certificate not yet valid")
	} else if now.After(notAfter) {
		daysSince := daysCeil(now.Sub(notAfter))
		job.Result.Add("basic_fields.validity.notAfter", StatusFail, fmt.Sprintf("certificate expired %d days ago", daysSince))
	} else {
		daysLeft := daysCeil(notAfter.Sub(now))
		job.Result.Add("basic_fields.validity", StatusPass, fmt.Sprintf("certificate valid - %d days left", daysLeft))
	}

	if rule.MinDays != nil {
		LintMinValidity(job, *rule.MinDays, now, notAfter)
	}

	if rule.MaxDays != nil {
		LintMaxValidity(job, *rule.MaxDays, notBefore, notAfter)
	}
}

func LintMinValidity(job *LintJob, minDays int, now, notAfter time.Time) {
	field := "basic_fields.validity.min_validity"

	if now.After(notAfter) {
		job.Result.Add(field, StatusFail, fmt.Sprintf("certificate expired; remaining days < %d", minDays))
		return
	}

	daysLeft := daysCeil(notAfter.Sub(now))
	msg := fmt.Sprintf("(%d days remaining >= %d days required)", daysLeft, minDays)

	status := StatusPass
	if daysLeft < minDays {
		status = StatusWarn
	}

	job.Result.Add(field, status, msg)
}

func LintMaxValidity(job *LintJob, maxDays int, notBefore, notAfter time.Time) {
	field := "basic_fields.validity.max_validity"

	if notAfter.Before(notBefore) {
		job.Result.Add(field, StatusFail, "notAfter is before notBefore (invalid validity period)")
		return
	}

	totalDays := daysCeil(notAfter.Sub(notBefore))
	msg := fmt.Sprintf("(%d days <= %d days maximum)", totalDays, maxDays)

	status := StatusPass
	if totalDays > maxDays {
		status = StatusFail
	}

	job.Result.Add(field, status, msg)
}

func daysCeil(d time.Duration) int {
	days := d.Hours() / 24
	if days == float64(int(days)) {
		return int(days)
	}
	return int(days) + 1
}

func LintNameRules(job *LintJob) {
	cert := job.Cert
	if job.Policy == nil || job.Policy.BasicFields == nil {
		return
	}

	if job.Policy.BasicFields.Issuer != nil {
		issuerNames := utils.GetIssuerNames(cert)
		LintNoWildcards(job, job.Policy.BasicFields.Issuer, issuerNames, "basic_fields.issuer")
	}

	if job.Policy.BasicFields.Subject != nil {
		subjectNames := utils.GetSubjectNames(cert)
		LintNoWildcards(job, job.Policy.BasicFields.Subject, subjectNames, "basic_fields.subject")
	}
}

func LintNoWildcards(job *LintJob, rule *policy.NameRule, names []string, field string) {
	if rule == nil {
		return
	}

	if rule.NoWildcards {
		wildcardFound := false
		for _, name := range names {
			if strings.Contains(name, "*") || strings.Contains(name, "?") {
				wildcardFound = true
				break
			}
		}

		status := StatusPass
		msg := "no wildcards found"
		if wildcardFound {
			status = StatusFail
			msg = "wildcards are forbidden but found in name(s)"
		}

		job.Result.Add(fmt.Sprintf("%s.no_wildcards", field), status, msg)
	}
}

func LintSignatureAlgorithm(job *LintJob) {
	cert := job.Cert
	if job.Policy.BasicFields == nil || job.Policy.BasicFields.SignatureAlgorithm == nil {
		return
	}
	rule := job.Policy.BasicFields.SignatureAlgorithm

	if len(rule.AllowedAlgorithms) == 0 {
		return
	}

	actual := cert.SignatureAlgorithm.String()
	allowed := rule.AllowedAlgorithms

	status := StatusFail
	message := ""

	if isSignatureAlgorithmAllowed(actual, allowed) {
		status = StatusPass
		message = fmt.Sprintf("signature algorithm allowed - %s", actual)
	} else {
		message = fmt.Sprintf("signature algorithm not allowed - %s", actual)
	}

	job.Result.Add("basic_fields.signature_algorithm", status, message)
}

func LintSignatureValidity(job *LintJob) {
	cert := job.Cert
	chain := job.Chain

	var issuer *x509.Certificate
	for _, c := range chain {
		if c.Subject.String() == cert.Issuer.String() {
			issuer = c
			break
		}
	}

	if issuer == nil {
		if cert.Subject.String() == cert.Issuer.String() {
			issuer = cert
		} else {
			job.Result.Add(
				"basic_fields.signature_valid",
				StatusFail,
				"issuer certificate not found in chain",
			)
			return
		}
	}

	err := issuer.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		job.Result.Add(
			"basic_fields.signature_valid",
			StatusFail,
			fmt.Sprintf("certificate signature is invalid: %v", err),
		)
	} else {
		job.Result.Add(
			"basic_fields.signature_valid",
			StatusPass,
			"certificate signature is cryptographically valid",
		)
	}
}

func isSignatureAlgorithmAllowed(actual string, allowed []string) bool {
	for _, algo := range allowed {
		if algo == "*" || algo == actual {
			return true
		}
	}
	return false
}

func LintSubjectPublicKeyInfo(job *LintJob) {
	if job.Policy.BasicFields == nil || job.Policy.BasicFields.SubjectPublicKeyInfo == nil {
		return
	}
	rule := job.Policy.BasicFields.SubjectPublicKeyInfo
	cert := job.Cert

	if rule.AllowedAlgorithms == nil || len(rule.AllowedAlgorithms) == 0 {
		return
	}

	algName := string(utils.GetPublicKeyAlgorithm(cert))
	algRule, ok := rule.AllowedAlgorithms[algName]
	if !ok {
		job.Result.Add(
			"basic_fields.subject_public_key_info",
			StatusFail,
			fmt.Sprintf("public key algorithm not allowed: %s", algName),
		)
		return
	}

	LintKeyAlgorithmRule(job, algName, cert.PublicKey, algRule)
}

func keyInfoField(algName string) string {
	return fmt.Sprintf("basic_fields.subject_public_key_info.%s", algName)
}

func (job *LintJob) addKeySizeCheck(algName, keyType string, actualSize, minRequired int) {
	field := keyInfoField(algName)
	if minRequired > 0 && actualSize < minRequired {
		job.Result.Add(field, StatusFail,
			fmt.Sprintf("%s key too small: %d bits, min required %d", keyType, actualSize, minRequired))
	} else {
		job.Result.Add(field, StatusPass,
			fmt.Sprintf("%s key size acceptable: %d bits", keyType, actualSize))
	}
}

func LintKeyAlgorithmRule(job *LintJob, algName string, pubKey any, rule *policy.KeyAlgorithmRule) {
	field := keyInfoField(algName)

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		job.addKeySizeCheck(algName, "RSA", key.N.BitLen(), rule.MinSize)

	case *dsa.PublicKey:
		job.addKeySizeCheck(algName, "DSA", key.P.BitLen(), rule.MinSize)

	case *ecdsa.PublicKey:
		if rule.MinSize > 0 && key.Params().BitSize < rule.MinSize {
			job.Result.Add(field, StatusFail,
				fmt.Sprintf("EC key too small: %d bits, min required %d", key.Params().BitSize, rule.MinSize))
			return
		}
		curveAllowed := len(rule.AllowedCurves) == 0 || slices.Contains(rule.AllowedCurves, key.Params().Name)
		job.Result.AddCheck(field, curveAllowed,
			fmt.Sprintf("EC key curve acceptable: %s", key.Params().Name),
			fmt.Sprintf("EC curve %s not allowed", key.Params().Name))

	case ed25519.PublicKey:
		job.Result.Add(field, StatusPass, "Ed25519 key is acceptable")

	default:
		job.Result.Add(field, StatusFail, fmt.Sprintf("unknown key type: %T", pubKey))
	}
}
