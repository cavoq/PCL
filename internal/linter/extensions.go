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

func (l *Linter) LintKeyUsage() {
	cert := l.Cert
	rule := l.Policy.Extensions
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

	if len(missing) == 0 {
		l.Result.Add("crypto.key_usage", StatusPass,
			fmt.Sprintf("required key usages present: %v", present))
	} else {
		l.Result.Add("crypto.key_usage", StatusFail,
			fmt.Sprintf("missing required key usages: %v", missing))
	}

	if pol.Critical {
		if isCritical(cert.Extensions, oidExtensionKeyUsage) {
			l.Result.Add("crypto.key_usage.critical", StatusPass, "KeyUsage extension is critical")
		} else {
			l.Result.Add("crypto.key_usage.critical", StatusFail, "KeyUsage extension is NOT critical")
		}
	}
}

func (l *Linter) LintExtendedKeyUsage() {
	cert := l.Cert
	rule := l.Policy.Extensions
	if rule == nil || rule.ExtendedKeyUsage == nil {
		return
	}

	pol := rule.ExtendedKeyUsage

	checks := []UsageCheck[x509.ExtKeyUsage]{
		{"serverAuth", pol.ServerAuth, x509.ExtKeyUsageServerAuth},
		{"clientAuth", pol.ClientAuth, x509.ExtKeyUsageClientAuth},
	}

	missing, present := checkSliceFlags(cert.ExtKeyUsage, checks)

	if len(missing) == 0 {
		l.Result.Add("crypto.extended_key_usage", StatusPass,
			fmt.Sprintf("required extended key usages present: %v", present))
	} else {
		l.Result.Add("crypto.extended_key_usage", StatusFail,
			fmt.Sprintf("missing required extended key usages: %v", missing))
	}

	if pol.Critical {
		if isCritical(cert.Extensions, oidExtensionExtendedKeyUsage) {
			l.Result.Add("crypto.extended_key_usage.critical", StatusPass, "ExtendedKeyUsage extension is critical")
		} else {
			l.Result.Add("crypto.extended_key_usage.critical", StatusFail, "ExtendedKeyUsage extension is NOT critical")
		}
	}
}

func (l *Linter) LintBasicConstraints() {
	cert := l.Cert
	rule := l.Policy.Extensions
	if rule == nil || rule.BasicConstraints == nil {
		return
	}

	pol := rule.BasicConstraints

	boolChecks := []UsageCheck[bool]{
		{"isCA", pol.IsCA, true},
	}

	missingBool, presentBool := checkBoolean(cert.IsCA, boolChecks)

	if len(missingBool) == 0 {
		if len(presentBool) > 0 {
			l.Result.Add("crypto.basic_constraints.is_ca", StatusPass,
				fmt.Sprintf("required basicConstraints isCA present: %v", presentBool))
		}
	} else {
		l.Result.Add("crypto.basic_constraints.is_ca", StatusFail,
			fmt.Sprintf("missing required basicConstraints isCA: %v", missingBool))
	}

	if pol.PathLenConstraint != nil {
		expected := *pol.PathLenConstraint

		actualPathLen := cert.MaxPathLen
		if cert.MaxPathLenZero {
			actualPathLen = 0
		}

		hasPathLen := actualPathLen != -1

		if !hasPathLen {
			l.Result.Add("crypto.basic_constraints.path_len", StatusFail,
				fmt.Sprintf("certificate missing pathLenConstraint, but policy requires %d", expected))
		} else if actualPathLen == expected {
			l.Result.Add("crypto.basic_constraints.path_len", StatusPass,
				fmt.Sprintf("pathLenConstraint matches required value: %d", expected))
		} else {
			l.Result.Add("crypto.basic_constraints.path_len", StatusFail,
				fmt.Sprintf("pathLenConstraint mismatch: expected %d, got %d", expected, actualPathLen))
		}
	}

	if pol.Critical {
		if isCritical(cert.Extensions, oidExtensionBasicConstraints) {
			l.Result.Add("crypto.basic_constraints.critical", StatusPass, "BasicConstraints extension is critical")
		} else {
			l.Result.Add("crypto.basic_constraints.critical", StatusFail, "BasicConstraints extension is NOT critical")
		}
	}
}
