package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"
)

var (
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
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
		job.addCriticalCheck("crypto.key_usage.critical", "KeyUsage", oidExtensionKeyUsage)
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
		job.addCriticalCheck("crypto.extended_key_usage.critical", "ExtendedKeyUsage", oidExtensionExtendedKeyUsage)
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
		job.addCriticalCheck("crypto.basic_constraints.critical", "BasicConstraints", oidExtensionBasicConstraints)
	}
}
