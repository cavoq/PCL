package policy

import (
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestRuleAppliesToInput_mixedRFC5280Style(t *testing.T) {
	certRule := rule.Rule{ID: "serial-number-present", Target: "certificate.serialNumber", Operator: "present"}
	crlRule := rule.Rule{ID: "crl-valid", Target: "crl", Operator: "crlValid", When: &rule.Condition{Target: "crl", Operator: "present"}}
	revokedRule := rule.Rule{
		ID:       "cert-not-revoked",
		Target:   "certificate",
		Operator: "notRevoked",
		When:     &rule.Condition{Target: "crl", Operator: "present"},
	}
	brCRL := rule.Rule{ID: "BR_CRL_VALID", Target: "crl", Operator: "crlValid", CertType: []string{"crl"}}

	if RuleAppliesToInput(certRule, InputCRL) {
		t.Fatal("certificate.serialNumber rule must not run on CRL input")
	}
	if !RuleAppliesToInput(crlRule, InputCRL) {
		t.Fatal("crl-valid must run on CRL input")
	}
	if RuleAppliesToInput(crlRule, InputCert) {
		t.Fatal("crl-valid must run only in the dedicated CRL pass")
	}
	if !RuleAppliesToInput(revokedRule, InputCert) {
		t.Fatal("cert-not-revoked must run on cert input")
	}
	if RuleAppliesToInput(revokedRule, InputCRL) {
		t.Fatal("cert-not-revoked must not run on CRL-only pass")
	}
	if !RuleAppliesToInput(brCRL, InputCRL) {
		t.Fatal("certType [crl] must run on CRL input")
	}
	if RuleAppliesToInput(brCRL, InputCert) {
		t.Fatal("certType [crl] must not run on intermediate cert input")
	}
}

func TestEvaluate_skipsCertificateRulesOnCRLContext(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "CRL Issuer"},
		AuthorityKeyId: []byte{0x01},
		ThisUpdate:     now,
		NextUpdate:     now.Add(24 * time.Hour),
	}
	tree := crl.BuildTree(revocationList)
	if tree == nil {
		t.Fatal("BuildTree returned nil")
	}

	reg := operator.DefaultRegistry()
	evalCtx := operator.NewEvaluationContext(
		tree,
		&cert.Info{Type: "crl", FilePath: "test.crl"},
		nil,
	)

	p := Policy{
		ID: "mixed",
		Rules: []rule.Rule{
			{ID: "cert-serial", Target: "certificate.serialNumber", Operator: "present", Severity: "error"},
			{ID: "crl-issuer", Target: "crl.issuer", Operator: "notEmpty", Severity: "error"},
		},
	}

	res := Evaluate(p, tree, reg, evalCtx)
	var serialVerdict, crlVerdict string
	for _, r := range res.Results {
		switch r.RuleID {
		case "cert-serial":
			serialVerdict = r.Verdict
		case "crl-issuer":
			crlVerdict = r.Verdict
		}
	}
	if serialVerdict != rule.VerdictSkip {
		t.Fatalf("cert-serial verdict = %q, want skip", serialVerdict)
	}
	if crlVerdict != rule.VerdictPass {
		t.Fatalf("crl-issuer verdict = %q, want pass", crlVerdict)
	}
}

func TestInputTypeFromContext(t *testing.T) {
	if inputTypeFromContext(operator.NewEvaluationContext(nil, &cert.Info{Type: "crl"}, nil)) != InputCRL {
		t.Fatal("crl type")
	}
	if inputTypeFromContext(operator.NewEvaluationContext(nil, &cert.Info{Type: "leaf"}, nil)) != InputCert {
		t.Fatal("leaf type")
	}
}

// Ensure unqualified custom targets still evaluate (unit-test policies).
func TestRuleAppliesToInput_unqualifiedTarget(t *testing.T) {
	r := rule.Rule{Target: "keySize", Operator: "eq"}
	if !RuleAppliesToInput(r, InputCRL) {
		t.Fatal("unqualified target should apply to any input")
	}
}

func TestRuleAppliesToInput_ocspInput(t *testing.T) {
	ocspRule := rule.Rule{ID: "ocsp-status", Target: "ocsp.status", Operator: "eq"}
	certRule := rule.Rule{ID: "cert-version", Target: "certificate.version", Operator: "eq"}
	if !RuleAppliesToInput(ocspRule, InputOCSP) {
		t.Fatal("ocsp.* must run on OCSP input")
	}
	if RuleAppliesToInput(certRule, InputOCSP) {
		t.Fatal("certificate.* must not run on OCSP-only pass")
	}
}

func TestRuleAppliesToInput_routesIndependentlyOfCertTypeContext(t *testing.T) {
	r := rule.Rule{Target: "certificate.version", Operator: "eq", CertType: []string{"leaf"}}
	if !RuleAppliesToInput(r, InputCert) {
		t.Fatal("certificate target must route to the certificate pass without role context")
	}
}

func TestRuleAppliesToInput_unknownInputTypeAllowsUnqualified(t *testing.T) {
	r := rule.Rule{Target: "customNode", Operator: "present"}
	if !RuleAppliesToInput(r, "other") {
		t.Fatal("unqualified rules should run for non-crl/non-ocsp input labels")
	}
}

func TestInputTypeFromContext_ocspAndNil(t *testing.T) {
	if inputTypeFromContext(nil) != InputCert {
		t.Fatal("nil ctx defaults to cert input")
	}
	if inputTypeFromContext(operator.NewEvaluationContext(nil, &cert.Info{Type: "ocsp"}, nil)) != InputOCSP {
		t.Fatal("ocsp cert type")
	}
}

func TestRuleAppliesToInput_certTypeOnLeaf(t *testing.T) {
	r := rule.Rule{Target: "certificate.version", Operator: "eq", CertType: []string{"leaf"}}
	if !RuleAppliesToInput(r, InputCert) {
		t.Fatal("certificate target must route to certificate input")
	}
	if RuleAppliesToInput(r, InputCRL) {
		t.Fatal("certificate target must not route to CRL input")
	}
}
