package linter

import (
	"bytes"
	"crypto/dsa" // #nosec G505 - deprecated but needed for legacy certificate validation
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

func LintSignatureAlgorithmMatch(job *LintJob) {
	cert := job.Cert
	field := "basic_fields.signature_algorithm_match"

	match, err := compareSignatureAlgorithms(cert.Raw)
	if err != nil {
		job.Result.Add(field, StatusWarn,
			fmt.Sprintf("unable to verify signature algorithm match: %v", err))
		return
	}

	if !match {
		job.Result.Add(field, StatusFail,
			"signature algorithm in TBSCertificate does not match outer signature algorithm")
		return
	}

	job.Result.Add(field, StatusPass,
		fmt.Sprintf("signature algorithm matches: %s", cert.SignatureAlgorithm.String()))
}

// compareSignatureAlgorithms parses the raw certificate and compares the
// signature algorithm OIDs in TBSCertificate and the outer Certificate structure.
func compareSignatureAlgorithms(rawCert []byte) (bool, error) {
	var cert rawCertificate
	_, err := asn1.Unmarshal(rawCert, &cert)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return bytes.Equal(cert.TBSCertificate.SignatureAlgorithm.FullBytes, cert.SignatureAlgorithm.FullBytes), nil
}

// ASN.1 structures for raw certificate parsing
type rawCertificate struct {
	TBSCertificate     rawTBSCertificate
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type rawTBSCertificate struct {
	Raw                asn1.RawContent
	Version            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           rawValidity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueID           asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString `asn1:"optional,tag:2"`
	Extensions         asn1.RawValue  `asn1:"optional,explicit,tag:3"`
}

type rawValidity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

func LintTimeEncoding(job *LintJob) {
	cert := job.Cert
	field := "basic_fields.time_encoding"

	var rawCert rawCertificate
	_, err := asn1.Unmarshal(cert.Raw, &rawCert)
	if err != nil {
		job.Result.Add(field, StatusWarn, fmt.Sprintf("failed to parse certificate: %v", err))
		return
	}

	notBeforeOK, notBeforeMsg := checkTimeEncoding(rawCert.TBSCertificate.Validity.NotBefore, "notBefore")
	notAfterOK, notAfterMsg := checkTimeEncoding(rawCert.TBSCertificate.Validity.NotAfter, "notAfter")

	if notBeforeOK {
		job.Result.Add(field+".notBefore", StatusPass, notBeforeMsg)
	} else {
		job.Result.Add(field+".notBefore", StatusFail, notBeforeMsg)
	}

	if notAfterOK {
		job.Result.Add(field+".notAfter", StatusPass, notAfterMsg)
	} else {
		job.Result.Add(field+".notAfter", StatusFail, notAfterMsg)
	}
}

func checkTimeEncoding(timeVal asn1.RawValue, timeName string) (bool, string) {
	const (
		tagUTCTime         = 23
		tagGeneralizedTime = 24
	)

	var t time.Time
	var err error

	switch timeVal.Tag {
	case tagUTCTime:
		_, err = asn1.Unmarshal(timeVal.FullBytes, &t)
		if err != nil {
			return false, fmt.Sprintf("failed to parse %s: %v", timeName, err)
		}
		if t.Year() >= 2050 {
			return false, fmt.Sprintf("%s uses UTCTime but year is %d (should use GeneralizedTime for 2050+)", timeName, t.Year())
		}
		return true, fmt.Sprintf("%s correctly uses UTCTime for year %d", timeName, t.Year())

	case tagGeneralizedTime:
		_, err = asn1.Unmarshal(timeVal.FullBytes, &t)
		if err != nil {
			return false, fmt.Sprintf("failed to parse %s: %v", timeName, err)
		}
		if t.Year() < 2050 {
			return false, fmt.Sprintf("%s uses GeneralizedTime but year is %d (should use UTCTime for dates through 2049)", timeName, t.Year())
		}
		// Check for fractional seconds (not allowed)
		if len(timeVal.Bytes) > 15 { // YYYYMMDDHHMMSSZ = 15 chars
			return false, fmt.Sprintf("%s GeneralizedTime contains fractional seconds", timeName)
		}
		return true, fmt.Sprintf("%s correctly uses GeneralizedTime for year %d", timeName, t.Year())

	default:
		return false, fmt.Sprintf("%s uses unknown time encoding (tag %d)", timeName, timeVal.Tag)
	}
}

func LintNonEmptyIssuer(job *LintJob) {
	cert := job.Cert
	field := "basic_fields.issuer_non_empty"

	if isNameEmpty(cert.Issuer) {
		job.Result.Add(field, StatusFail, "issuer DN is empty")
		return
	}

	job.Result.Add(field, StatusPass, "issuer DN is non-empty")
}

func isNameEmpty(name pkix.Name) bool {
	return len(name.Country) == 0 &&
		len(name.Organization) == 0 &&
		len(name.OrganizationalUnit) == 0 &&
		len(name.Locality) == 0 &&
		len(name.Province) == 0 &&
		len(name.StreetAddress) == 0 &&
		len(name.PostalCode) == 0 &&
		name.SerialNumber == "" &&
		name.CommonName == "" &&
		len(name.Names) == 0 &&
		len(name.ExtraNames) == 0
}

func LintEmptySubjectSANCritical(job *LintJob) {
	cert := job.Cert
	field := "basic_fields.empty_subject_san"

	if !isNameEmpty(cert.Subject) {
		job.Result.Add(field, StatusPass, "subject DN is non-empty")
		return
	}

	hasSAN := len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 ||
		len(cert.IPAddresses) > 0 || len(cert.URIs) > 0

	if !hasSAN {
		job.Result.Add(field, StatusFail,
			"subject DN is empty but SubjectAlternativeName extension is missing")
		return
	}

	sanCritical := isCritical(cert.Extensions, policy.ExtSubjectAltName.OID)
	if !sanCritical {
		job.Result.Add(field, StatusFail,
			"subject DN is empty but SubjectAlternativeName extension is not critical")
		return
	}

	job.Result.Add(field, StatusPass,
		"subject DN is empty with critical SubjectAlternativeName extension")
}
