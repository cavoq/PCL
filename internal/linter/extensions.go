package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/policy"
)

type UsageCheck[T any] struct {
	Name     string
	Required bool
	Flag     T
}

func checkSliceFlags[T comparable](actual []T, checks []UsageCheck[T]) (missing []string, present []string) {
	for _, c := range checks {
		if !c.Required {
			continue
		}
		found := slices.Contains(actual, c.Flag)
		if found {
			present = append(present, c.Name)
		} else {
			missing = append(missing, c.Name)
		}
	}
	return
}

func checkBitmaskFlags(actual x509.KeyUsage, checks []UsageCheck[x509.KeyUsage]) (missing []string, present []string) {
	for _, c := range checks {
		if !c.Required {
			continue
		}
		if actual&c.Flag != 0 {
			present = append(present, c.Name)
		} else {
			missing = append(missing, c.Name)
		}
	}
	return
}

func checkBoolean(actual bool, checks []UsageCheck[bool]) (missing []string, present []string) {
	for _, c := range checks {
		if !c.Required {
			continue
		}
		if actual == c.Flag {
			present = append(present, c.Name)
		} else {
			missing = append(missing, c.Name)
		}
	}
	return
}

func isCritical(exts []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, e := range exts {
		if e.Id.Equal(oid) {
			return e.Critical
		}
	}
	return false
}

func (job *LintJob) addCriticalCheck(id, extName string, oid asn1.ObjectIdentifier) {
	critical := isCritical(job.Cert.Extensions, oid)
	job.Result.AddCheck(
		id,
		critical,
		extName+" extension is critical",
		extName+" extension is NOT critical",
	)
}

func LintKeyUsage(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.KeyUsage == nil {
		return
	}

	pol := rule.KeyUsage
	checks := []UsageCheck[x509.KeyUsage]{
		{"digitalSignature", pol.DigitalSignature, x509.KeyUsageDigitalSignature},
		{"keyEncipherment", pol.KeyEncipherment, x509.KeyUsageKeyEncipherment},
		{"keyCertSign", pol.KeyCertSign, x509.KeyUsageCertSign},
		{"cRLSign", pol.CRLSign, x509.KeyUsageCRLSign},
	}

	missing, present := checkBitmaskFlags(cert.KeyUsage, checks)
	job.Result.AddRequirementCheck("crypto.key_usage", missing, present, "key usages")

	if pol.Critical {
		job.addCriticalCheck("crypto.key_usage.critical", "KeyUsage", policy.OIDKeyUsage)
	}
}

func LintExtendedKeyUsage(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.ExtendedKeyUsage == nil {
		return
	}

	pol := rule.ExtendedKeyUsage
	checks := []UsageCheck[x509.ExtKeyUsage]{
		{"serverAuth", pol.ServerAuth, x509.ExtKeyUsageServerAuth},
		{"clientAuth", pol.ClientAuth, x509.ExtKeyUsageClientAuth},
	}

	missing, present := checkSliceFlags(cert.ExtKeyUsage, checks)
	job.Result.AddRequirementCheck("crypto.extended_key_usage", missing, present, "extended key usages")

	if pol.Critical {
		job.addCriticalCheck("crypto.extended_key_usage.critical", "ExtendedKeyUsage", policy.OIDExtendedKeyUsage)
	}
}

func getActualPathLen(cert *x509.Certificate) int {
	if cert.MaxPathLenZero {
		return 0
	}
	return cert.MaxPathLen
}

func (job *LintJob) validatePathLenConstraint(expected int) {
	actual := getActualPathLen(job.Cert)

	switch actual {
	case -1:
		job.Result.Add("crypto.basic_constraints.path_len", StatusFail,
			fmt.Sprintf("certificate missing pathLenConstraint, but policy requires %d", expected))
	case expected:
		job.Result.Add("crypto.basic_constraints.path_len", StatusPass,
			fmt.Sprintf("pathLenConstraint matches required value: %d", expected))
	default:
		job.Result.Add("crypto.basic_constraints.path_len", StatusFail,
			fmt.Sprintf("pathLenConstraint mismatch: expected %d, got %d", expected, actual))
	}
}

func LintBasicConstraints(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.BasicConstraints == nil {
		return
	}

	pol := rule.BasicConstraints

	checks := []UsageCheck[bool]{
		{"isCA", pol.IsCA, true},
	}
	missing, present := checkBoolean(cert.IsCA, checks)
	if len(missing) == 0 && len(present) > 0 {
		job.Result.Add("crypto.basic_constraints.is_ca", StatusPass,
			fmt.Sprintf("required basicConstraints isCA present: %v", present))
	} else if len(missing) > 0 {
		job.Result.Add("crypto.basic_constraints.is_ca", StatusFail,
			fmt.Sprintf("missing required basicConstraints isCA: %v", missing))
	}

	if pol.PathLenConstraint != nil {
		job.validatePathLenConstraint(*pol.PathLenConstraint)
	}

	if pol.Critical {
		job.addCriticalCheck("crypto.basic_constraints.critical", "BasicConstraints", policy.OIDBasicConstraints)
	}
}

func LintAuthorityKeyID(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.AuthorityKeyID == nil {
		return
	}

	pol := rule.AuthorityKeyID

	if pol.Required {
		hasAKI := len(cert.AuthorityKeyId) > 0
		if hasAKI {
			job.Result.Add("extensions.authority_key_id", StatusPass,
				fmt.Sprintf("Authority Key Identifier present (%d bytes)", len(cert.AuthorityKeyId)))
		} else {
			job.Result.Add("extensions.authority_key_id", StatusFail,
				"Authority Key Identifier extension is missing (required per RFC 5280 for non-self-signed certificates)")
		}
	}

	if pol.Critical {
		job.addCriticalCheck("extensions.authority_key_id.critical", "AuthorityKeyIdentifier", policy.OIDAKI)
	}
}

func LintSubjectKeyID(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.SubjectKeyID == nil {
		return
	}

	pol := rule.SubjectKeyID

	if pol.Required {
		hasSKI := len(cert.SubjectKeyId) > 0
		if hasSKI {
			job.Result.Add("extensions.subject_key_id", StatusPass,
				fmt.Sprintf("Subject Key Identifier present (%d bytes)", len(cert.SubjectKeyId)))
		} else {
			job.Result.Add("extensions.subject_key_id", StatusFail,
				"Subject Key Identifier extension is missing (required per RFC 5280 for CA certificates)")
		}
	}

	if pol.Critical {
		job.addCriticalCheck("extensions.subject_key_id.critical", "SubjectKeyIdentifier", policy.OIDSKI)
	}
}

func LintSAN(job *LintJob) {
	rule := job.Policy.Extensions
	if rule == nil || rule.SAN == nil {
		return
	}

	pol := rule.SAN

	allSANs := collectSANs(job)

	if pol.Required {
		if len(allSANs) > 0 {
			job.Result.Add("extensions.san", StatusPass,
				fmt.Sprintf("Subject Alternative Name present with %d entries", len(allSANs)))
		} else {
			job.Result.Add("extensions.san", StatusFail,
				"Subject Alternative Name extension is missing or empty")
		}
	}

	if pol.NoWildcards && len(allSANs) > 0 {
		wildcardFound := false
		for _, san := range allSANs {
			if strings.Contains(san, "*") || strings.Contains(san, "?") {
				wildcardFound = true
				break
			}
		}
		if wildcardFound {
			job.Result.Add("extensions.san.no_wildcards", StatusFail,
				"SAN contains wildcard entries (policy forbids wildcards)")
		} else {
			job.Result.Add("extensions.san.no_wildcards", StatusPass,
				"SAN contains no wildcard entries")
		}
	}

	if len(pol.Allowed) > 0 && len(allSANs) > 0 {
		lintSANPatterns(job, allSANs, pol.Allowed, true)
	}

	if len(pol.Forbidden) > 0 && len(allSANs) > 0 {
		lintSANPatterns(job, allSANs, pol.Forbidden, false)
	}

	if pol.Critical {
		job.addCriticalCheck("extensions.san.critical", "SubjectAlternativeName", policy.OIDSAN)
	}
}

func collectSANs(job *LintJob) []string {
	cert := job.Cert
	var sans []string

	sans = append(sans, cert.DNSNames...)

	for _, email := range cert.EmailAddresses {
		sans = append(sans, email)
	}

	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}

func lintSANPatterns(job *LintJob, sans []string, patterns []string, allowed bool) {
	field := "extensions.san.allowed"
	if !allowed {
		field = "extensions.san.forbidden"
	}

	for _, san := range sans {
		matched := false
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				job.Result.Add(field, StatusFail,
					fmt.Sprintf("invalid regex pattern: %s", pattern))
				return
			}
			if re.MatchString(san) {
				matched = true
				break
			}
		}

		if allowed && !matched {
			job.Result.Add(field, StatusFail,
				fmt.Sprintf("SAN entry '%s' does not match any allowed pattern", san))
			return
		}
		if !allowed && matched {
			job.Result.Add(field, StatusFail,
				fmt.Sprintf("SAN entry '%s' matches a forbidden pattern", san))
			return
		}
	}

	if allowed {
		job.Result.Add(field, StatusPass, "all SAN entries match allowed patterns")
	} else {
		job.Result.Add(field, StatusPass, "no SAN entries match forbidden patterns")
	}
}

func LintCRLDistributionPoints(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.CRLDistributionPoints == nil {
		return
	}

	pol := rule.CRLDistributionPoints

	hasCRL := len(cert.CRLDistributionPoints) > 0

	if hasCRL {
		job.Result.Add("extensions.crl_distribution_points", StatusPass,
			fmt.Sprintf("CRL Distribution Points present with %d URLs", len(cert.CRLDistributionPoints)))
	} else {
		job.Result.Add("extensions.crl_distribution_points", StatusFail,
			"CRL Distribution Points extension is missing")
	}

	if len(pol.URLs) > 0 && hasCRL {
		missing := []string{}
		for _, expected := range pol.URLs {
			found := false
			for _, actual := range cert.CRLDistributionPoints {
				if actual == expected {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, expected)
			}
		}
		if len(missing) > 0 {
			job.Result.Add("extensions.crl_distribution_points.urls", StatusFail,
				fmt.Sprintf("missing expected CRL URLs: %v", missing))
		} else {
			job.Result.Add("extensions.crl_distribution_points.urls", StatusPass,
				"all expected CRL URLs present")
		}
	}

	if pol.Critical {
		job.addCriticalCheck("extensions.crl_distribution_points.critical", "CRLDistributionPoints", policy.OIDCRLDistPoints)
	}
}

func LintAuthorityInfoAccess(job *LintJob) {
	cert := job.Cert
	rule := job.Policy.Extensions
	if rule == nil || rule.AuthorityInfoAccess == nil {
		return
	}

	pol := rule.AuthorityInfoAccess

	hasOCSP := len(cert.OCSPServer) > 0
	hasIssuers := len(cert.IssuingCertificateURL) > 0
	hasAIA := hasOCSP || hasIssuers

	if hasAIA {
		job.Result.Add("extensions.authority_info_access", StatusPass,
			fmt.Sprintf("Authority Information Access present (OCSP: %d, CA Issuers: %d)",
				len(cert.OCSPServer), len(cert.IssuingCertificateURL)))
	} else {
		job.Result.Add("extensions.authority_info_access", StatusFail,
			"Authority Information Access extension is missing")
	}

	if len(pol.OCSP) > 0 {
		missing := []string{}
		for _, expected := range pol.OCSP {
			found := false
			for _, actual := range cert.OCSPServer {
				if actual == expected {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, expected)
			}
		}
		if len(missing) > 0 {
			job.Result.Add("extensions.authority_info_access.ocsp", StatusFail,
				fmt.Sprintf("missing expected OCSP URLs: %v", missing))
		} else {
			job.Result.Add("extensions.authority_info_access.ocsp", StatusPass,
				"all expected OCSP URLs present")
		}
	}

	if len(pol.CAIssuers) > 0 {
		missing := []string{}
		for _, expected := range pol.CAIssuers {
			found := false
			for _, actual := range cert.IssuingCertificateURL {
				if actual == expected {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, expected)
			}
		}
		if len(missing) > 0 {
			job.Result.Add("extensions.authority_info_access.ca_issuers", StatusFail,
				fmt.Sprintf("missing expected CA Issuer URLs: %v", missing))
		} else {
			job.Result.Add("extensions.authority_info_access.ca_issuers", StatusPass,
				"all expected CA Issuer URLs present")
		}
	}

	if pol.Critical {
		job.addCriticalCheck("extensions.authority_info_access.critical", "AuthorityInfoAccess", policy.OIDAIA)
	}
}
