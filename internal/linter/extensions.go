package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"
)

var (
	oidExtensionKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
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
}
