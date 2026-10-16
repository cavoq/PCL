package policy

import (
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/rule"
)

func TestParse_GroupsShareFieldsWithTheirRules(t *testing.T) {
	p, err := Parse([]byte(`
id: test-policy
rules:
  - {id: first, target: certificate.version, operator: present, severity: error}
groups:
  - id: section
    title: Section 1
    reference: SPEC 1
    requirement: should
    certType: [leaf]
    effective: {basis: issuance, from: 2023-09-15}
    when: {target: certificate.extensions, operator: present}
    rules:
      - {id: inherits, target: certificate.version, operator: present}
      - id: overrides
        target: certificate.version
        operator: present
        reference: SPEC 1.2
        requirement: must
        severity: warning
        certType: [root]
        effective: {basis: validation, until: 2030-01-01}
        when: {target: certificate.subject, operator: present}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 3 || p.Rules[0].ID != "first" || p.Groups != nil {
		t.Fatalf("rules = %v, groups = %v; want the policy's rule first and no groups", p.Rules, p.Groups)
	}
	inherits, overrides := p.Rules[1], p.Rules[2]
	if inherits.Reference != "SPEC 1" || inherits.Requirement != rule.RequirementShould ||
		inherits.Severity != rule.SeverityWarning || strings.Join(inherits.CertType, ",") != "leaf" ||
		inherits.Effective == nil || inherits.Effective.Basis != rule.EffectiveByIssuance ||
		inherits.When == nil || inherits.When.Target != "certificate.extensions" {
		t.Errorf("inherited rule = %+v", inherits)
	}
	if overrides.Reference != "SPEC 1.2" || overrides.Requirement != rule.RequirementMust ||
		overrides.Severity != rule.SeverityWarning || strings.Join(overrides.CertType, ",") != "root" ||
		overrides.Effective.Basis != rule.EffectiveByValidation {
		t.Errorf("overriding rule = %+v", overrides)
	}
	if when := overrides.When; when == nil || len(when.AllOf) != 2 ||
		when.AllOf[0].Target != "certificate.extensions" || when.AllOf[1].Target != "certificate.subject" {
		t.Errorf("combined condition = %+v, want the group's and the rule's", overrides.When)
	}
}

func TestParse_RejectsInvalidGroups(t *testing.T) {
	rules := "    rules: [{id: r, target: certificate.version, operator: present, severity: error}]\n"
	for name, test := range map[string]struct{ groups, want string }{
		"missing id":          {"  - title: x\n" + rules, "group 0: id is required"},
		"duplicate id":        {"  - id: g\n" + rules + "  - id: g\n" + strings.Replace(rules, "id: r", "id: s", 1), `duplicate group id "g"`},
		"no rules":            {"  - id: g\n    rules: []\n", "group g: rules are required"},
		"invalid requirement": {"  - id: g\n    requirement: must-not\n" + rules, "group g: invalid requirement"},
		"invalid certType":    {"  - id: g\n    certType: [nope]\n" + rules, "group g certType"},
		"invalid when":        {"  - id: g\n    when: {target: certificate.version}\n" + rules, "group g: when.operator is required"},
		"duplicate rule id":   {"  - id: g\n" + rules + "  - id: h\n" + rules, `duplicate rule id "r"`},
	} {
		_, err := Parse([]byte("id: test-policy\ngroups:\n" + test.groups))
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestParse_CompoundConditions(t *testing.T) {
	valid := `
id: test-policy
rules:
  - id: r
    target: certificate.version
    operator: present
    severity: error
    when:
      allOf:
        - {target: certificate.extensions, operator: present}
        - not: {anyOf: [{target: crl.version, operator: present}, {target: certificate.subject, operator: absent}]}
`
	p, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if scope := scopeForRule(p.Rules[0]); !scope.dependencies.contains(crlInput) {
		t.Errorf("dependencies = %v, want the crl target of a nested condition", scope.dependencies)
	}
	for name, test := range map[string]struct{ when, want string }{
		"two forms":      {"{target: certificate.version, operator: present, not: {target: a, operator: present}}", "use one of target/operator, allOf, anyOf or not"},
		"single allOf":   {"{allOf: [{target: a, operator: present}]}", "when.allOf needs at least two conditions"},
		"nested invalid": {"{anyOf: [{target: a, operator: present}, {target: b}]}", "when.anyOf[1].operator is required"},
	} {
		_, err := Parse([]byte("id: p\nrules:\n  - {id: r, target: a, operator: present, severity: error, when: " + test.when + "}\n"))
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}
