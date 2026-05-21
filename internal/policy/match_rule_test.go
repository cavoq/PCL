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

	crlCtx := operator.NewEvaluationContext(nil, &cert.Info{Type: "crl"}, nil)
	certCtx := operator.NewEvaluationContext(nil, &cert.Info{Type: "intermediate"}, nil)

	if RuleAppliesToInput(certRule, InputCRL, crlCtx) {
		t.Fatal("certificate.serialNumber rule must not run on CRL input")
	}
	if !RuleAppliesToInput(crlRule, InputCRL, crlCtx) {
		t.Fatal("crl-valid must run on CRL input")
	}
	if !RuleAppliesToInput(crlRule, InputCert, certCtx) {
		t.Fatal("crl-valid must run when CRL is embedded in cert tree pass")
	}
	if !RuleAppliesToInput(revokedRule, InputCert, certCtx) {
		t.Fatal("cert-not-revoked must run on cert input")
	}
	if RuleAppliesToInput(revokedRule, InputCRL, crlCtx) {
		t.Fatal("cert-not-revoked must not run on CRL-only pass")
	}
	if !RuleAppliesToInput(brCRL, InputCRL, crlCtx) {
		t.Fatal("certType [crl] must run on CRL input")
	}
	if RuleAppliesToInput(brCRL, InputCert, certCtx) {
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
	ctx := operator.NewEvaluationContext(nil, &cert.Info{Type: "crl"}, nil)
	if !RuleAppliesToInput(r, InputCRL, ctx) {
		t.Fatal("unqualified target should apply to any input")
	}
}

func TestRuleAppliesToInput_certTypeOnLeaf(t *testing.T) {
	r := rule.Rule{Target: "certificate.version", Operator: "eq", CertType: []string{"leaf"}}
	leafCtx := operator.NewEvaluationContext(nil, &cert.Info{Type: "leaf"}, nil)
	crlCtx := operator.NewEvaluationContext(nil, &cert.Info{Type: "crl"}, nil)
	if !RuleAppliesToInput(r, InputCert, leafCtx) {
		t.Fatal("leaf certType on leaf")
	}
	if RuleAppliesToInput(r, InputCert, crlCtx) {
		t.Fatal("leaf certType must not run when evaluating crl object")
	}
}
