package linter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type UsageCheck struct {
	Name     string
	Required bool
	Flag     x509.KeyUsage
}

func CheckUsages(actual x509.KeyUsage, checks []UsageCheck) (missing []string, present []string) {
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

	checks := []UsageCheck{
		{"digitalSignature", pol.DigitalSignature, x509.KeyUsageDigitalSignature},
		{"keyEncipherment", pol.KeyEncipherment, x509.KeyUsageKeyEncipherment},
		{"keyCertSign", pol.KeyCertSign, x509.KeyUsageCertSign},
		{"cRLSign", pol.CRLSign, x509.KeyUsageCRLSign},
	}

	missing, present := CheckUsages(cert.KeyUsage, checks)

	if len(missing) == 0 {
		l.Result.Add("crypto.key_usage", StatusPass,
			fmt.Sprintf("required key usages present: %v", present))
	} else {
		l.Result.Add("crypto.key_usage", StatusFail,
			fmt.Sprintf("missing required key usages: %v", missing))
	}

	if pol.Critical {
		if isCritical(cert.Extensions, asn1.ObjectIdentifier{2, 5, 29, 15}) {
			l.Result.Add("crypto.key_usage.critical", StatusPass, "KeyUsage extension is critical")
		} else {
			l.Result.Add("crypto.key_usage.critical", StatusFail, "KeyUsage extension is NOT critical")
		}
	}
}
