package policy

import (
	"testing"

	stdasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

func TestPolicyScopeInferenceIsOrderIndependent(t *testing.T) {
	certificateRule := rule.Rule{Target: "certificate.version"}
	crlRule := rule.Rule{Target: "crl.nextUpdate"}
	ocspRule := rule.Rule{Target: "ocsp.status"}

	orders := [][]rule.Rule{
		{certificateRule, crlRule, ocspRule},
		{ocspRule, certificateRule, crlRule},
		{crlRule, ocspRule, certificateRule},
	}
	for index, rules := range orders {
		policy := Policy{ID: "mixed", Rules: rules}
		for _, input := range []string{InputCert, InputCRL, InputOCSP} {
			if !AppliesToInput(policy, input) {
				t.Errorf("order %d does not apply to %s", index, input)
			}
		}
		for _, input := range []string{InputTST, InputSCT, InputAttrCert} {
			if AppliesToInput(policy, input) {
				t.Errorf("order %d unexpectedly applies to %s", index, input)
			}
		}
	}
}

func TestPolicyScopeExplicitAppliesToTakesPrecedence(t *testing.T) {
	policy := Policy{
		ID:        "explicit",
		AppliesTo: []string{InputOCSP},
		Rules: []rule.Rule{
			{Target: "certificate.version"},
			{Target: "crl.nextUpdate"},
		},
	}

	if !AppliesToInput(policy, InputOCSP) {
		t.Fatal("explicit OCSP scope was not selected")
	}
	if AppliesToInput(policy, InputCert) || AppliesToInput(policy, InputCRL) {
		t.Fatal("inferred targets must not widen explicit appliesTo")
	}
}

func TestRuleScopeTreatsConditionInputsAsDependencies(t *testing.T) {
	candidate := rule.Rule{
		Target: "certificate.serialNumber",
		When: &rule.Condition{
			Target: "ocsp.status",
		},
	}

	scope := scopeForRule(candidate)
	if !scope.primaryQualified || scope.primary != certificateInput {
		t.Fatalf("primary = (%q, %t), want qualified certificate", scope.primary, scope.primaryQualified)
	}
	if !scope.dependencies.contains(ocspInput) {
		t.Fatal("OCSP condition was not recorded as a dependency")
	}
	if !RuleAppliesToInput(candidate, InputCert) {
		t.Fatal("certificate target must execute in the certificate pass")
	}
	if RuleAppliesToInput(candidate, InputOCSP) {
		t.Fatal("OCSP condition must not move a certificate rule to the OCSP pass")
	}

	policy := Policy{Rules: []rule.Rule{candidate}}
	if !AppliesToInput(policy, InputCert) || AppliesToInput(policy, InputOCSP) {
		t.Fatal("policy inference must use the primary target, not its condition")
	}
}

func TestUnqualifiedRuleMakesInferredPolicyInputAgnostic(t *testing.T) {
	qualified := rule.Rule{Target: "certificate.version"}
	unqualified := rule.Rule{Target: "custom.value"}

	for index, rules := range [][]rule.Rule{
		{qualified, unqualified},
		{unqualified, qualified},
	} {
		policy := Policy{Rules: rules}
		for _, input := range []string{
			InputCert,
			InputCRL,
			InputOCSP,
			InputTST,
			InputSCT,
			InputAttrCert,
		} {
			if !AppliesToInput(policy, input) {
				t.Errorf("order %d: unqualified rule did not make policy apply to %s", index, input)
			}
		}
	}
}

func TestRuleScopeRoutesOnlyByPrimaryInput(t *testing.T) {
	candidate := rule.Rule{
		Target:   "certificate.version",
		CertType: []string{"leaf"},
	}
	if !RuleAppliesToInput(candidate, InputCert) {
		t.Fatal("certificate target must route without role context")
	}
	if RuleAppliesToInput(candidate, InputCRL) {
		t.Fatal("matching role must not override a mismatched input namespace")
	}
}

func TestEvaluateOwnsRuleRoleFiltering(t *testing.T) {
	root := node.New(node.CertificateNamespace, nil)
	root.Children["version"] = node.New("version", 3)
	policy := Policy{
		ID: "role-filtering",
		Rules: []rule.Rule{{
			ID:       "leaf-version",
			Target:   "certificate.version",
			Operator: "present",
			Severity: rule.SeverityError,
			CertType: []string{"leaf"},
		}},
	}

	withoutRole := Evaluate(policy, root, operator.DefaultRegistry(), nil)
	if got := withoutRole.Results[0].Verdict; got != rule.VerdictSkip {
		t.Fatalf("nil role context verdict = %q, want skip", got)
	}

	leafContext := operator.NewEvaluationContext(root, &cert.Info{Type: "leaf"}, nil)
	withRole := Evaluate(policy, root, operator.DefaultRegistry(), leafContext)
	if got := withRole.Results[0].Verdict; got != rule.VerdictPass {
		t.Fatalf("leaf role context verdict = %q, want pass", got)
	}
}

func TestParseRejectsOIDRuleRole(t *testing.T) {
	_, err := Parse([]byte(`
id: invalid-rule-role
rules:
  - id: custom-oid-role
    target: certificate.version
    operator: present
    severity: error
    certType: [1.2.3.4]
`))
	if err == nil {
		t.Fatal("rule certType OID has no runtime role semantics and must be rejected")
	}
}

func TestInputTypeFromContextCoversDeclaredInputs(t *testing.T) {
	tests := []struct {
		name string
		ctx  *operator.EvaluationContext
		want string
	}{
		{name: "nil defaults to certificate", want: InputCert},
		{name: "empty defaults to certificate", ctx: &operator.EvaluationContext{}, want: InputCert},
		{name: "certificate role", ctx: &operator.EvaluationContext{Cert: &cert.Info{Type: "root"}}, want: InputCert},
		{name: "crl type", ctx: &operator.EvaluationContext{Cert: &cert.Info{Type: InputCRL}}, want: InputCRL},
		{name: "ocsp type", ctx: &operator.EvaluationContext{Cert: &cert.Info{Type: InputOCSP}}, want: InputOCSP},
		{name: "tst type", ctx: &operator.EvaluationContext{Cert: &cert.Info{Type: InputTST}}, want: InputTST},
		{name: "sct type", ctx: &operator.EvaluationContext{Cert: &cert.Info{Type: InputSCT}}, want: InputSCT},
		{name: "attribute certificate type", ctx: &operator.EvaluationContext{Cert: &cert.Info{Type: InputAttrCert}}, want: InputAttrCert},
		{
			name: "tree identifies evaluated object",
			ctx: &operator.EvaluationContext{
				Root: node.New(node.CRLNamespace, nil),
				Cert: &cert.Info{Type: "leaf"},
			},
			want: InputCRL,
		},
		{name: "tst tree without cert info", ctx: &operator.EvaluationContext{Root: node.New(node.TSTNamespace, nil)}, want: InputTST},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := inputTypeFromContext(test.ctx); got != test.want {
				t.Fatalf("inputTypeFromContext() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPolicyCertificateScopeMatchesUnknownEKUOID(t *testing.T) {
	policy := Policy{
		CertType: []string{"1.2.3.4"},
		Rules:    []rule.Rule{{Target: "certificate.version"}},
	}
	certificate := &x509.Certificate{
		UnknownExtKeyUsage: []stdasn1.ObjectIdentifier{{1, 2, 3, 4}},
	}

	if !AppliesToCertificate(policy, certificate) {
		t.Fatal("custom EKU OID accepted by policy validation must match UnknownExtKeyUsage")
	}
}
