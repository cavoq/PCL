package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

const profilePolicy = `
id: profiles
profiles:
  - id: constrained-ca
    role: intermediate
    when: {target: certificate.nameConstraints, operator: present}
  - id: cross-certified-ca
    role: intermediate
    assumeOnly: true
  - id: ca
    role: intermediate
  - id: subscriber
    role: leaf
rules:
  - {id: any, target: certificate.version, operator: present, severity: error}
  - {id: constrained, target: certificate.version, operator: present, severity: error, profile: [constrained-ca]}
  - {id: issuing, target: certificate.version, operator: present, severity: error, profile: [constrained-ca, ca]}
  - {id: cross, target: certificate.version, operator: present, severity: error, profile: [cross-certified-ca]}
`

func TestProfileSelection(t *testing.T) {
	p, err := Parse([]byte(profilePolicy))
	if err != nil {
		t.Fatal(err)
	}
	reg := operator.NewRegistry()
	reg.Register(operator.Present{})
	tree := func(constrained bool) *node.Node {
		certificate := node.New("certificate", nil)
		certificate.Children["version"] = node.New("version", 3)
		if constrained {
			certificate.Children["nameConstraints"] = node.New("nameConstraints", nil)
		}
		root := node.New("root", nil)
		root.Children["certificate"] = certificate
		return root
	}
	tests := []struct {
		name, kind   string
		constrained  bool
		assumed      []string
		profile      string
		basis        string
		evaluated    []string
		skipMessages map[string]string
	}{
		{name: "first match by condition", kind: "intermediate", constrained: true,
			profile: "constrained-ca", basis: ProfileInferred, evaluated: []string{"any", "constrained", "issuing"}},
		{name: "fallback without condition", kind: "intermediate",
			profile: "ca", basis: ProfileInferred, evaluated: []string{"any", "issuing"},
			skipMessages: map[string]string{"cross": "applies to profiles cross-certified-ca; evaluated as ca (inferred)"}},
		{name: "assumed profile wins", kind: "intermediate", constrained: true, assumed: []string{"cross-certified-ca"},
			profile: "cross-certified-ca", basis: ProfileAssumed, evaluated: []string{"any", "cross"}},
		{name: "assumption for another role is ignored", kind: "leaf", assumed: []string{"cross-certified-ca"},
			profile: "subscriber", basis: ProfileInferred, evaluated: []string{"any"}},
		{name: "no profile for the role", kind: "root",
			evaluated:    []string{"any"},
			skipMessages: map[string]string{"issuing": "applies to profiles constrained-ca, ca; no profile of the policy applies to this root"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &operator.EvaluationContext{Input: operator.Input{Kind: test.kind}, AssumedProfiles: test.assumed}
			result := Evaluate(p, tree(test.constrained), reg, ctx)
			if result.Profile != test.profile || result.ProfileBasis != test.basis {
				t.Errorf("profile = %q (%s), want %q (%s)", result.Profile, result.ProfileBasis, test.profile, test.basis)
			}
			var evaluated []string
			for _, r := range result.Results {
				if r.Verdict != rule.VerdictSkip {
					evaluated = append(evaluated, r.RuleID)
					continue
				}
				if want, ok := test.skipMessages[r.RuleID]; ok {
					if r.Findings[0].Code != rule.CodeProfile || r.Findings[0].Message != want {
						t.Errorf("%s skipped with %s %q, want %q", r.RuleID, r.Findings[0].Code, r.Findings[0].Message, want)
					}
				}
			}
			if strings.Join(evaluated, ",") != strings.Join(test.evaluated, ",") {
				t.Errorf("evaluated %v, want %v", evaluated, test.evaluated)
			}
		})
	}
}

func TestParse_RejectsInvalidProfiles(t *testing.T) {
	rule := "rules: [{id: r, target: certificate.version, operator: present, severity: error, profile: [p]}]\n"
	for name, test := range map[string]struct{ policy, want string }{
		"missing id":           {"profiles: [{role: leaf}]\n", "profile 0: id is required"},
		"duplicate id":         {"profiles: [{id: p, role: leaf}, {id: p, role: root}]\n", `duplicate profile id "p"`},
		"unknown role":         {"profiles: [{id: p, role: ca}]\n", `profile p: role "ca" is not a rule role`},
		"assumeOnly with when": {"profiles: [{id: p, role: leaf, assumeOnly: true, when: {target: a, operator: present}}]\n", "takes no when"},
		"invalid when":         {"profiles: [{id: p, role: leaf, when: {target: a}}]\n", "profile p: when.operator is required"},
		"unknown profile":      {rule, `rule r: unknown profile "p"`},
		"duplicate reference":  {"profiles: [{id: p, role: leaf}]\nrules: [{id: r, target: a, operator: present, severity: error, profile: [p, p]}]\n", `duplicate profile "p"`},
		"certType excludes":    {"profiles: [{id: p, role: leaf}]\nrules: [{id: r, target: a, operator: present, severity: error, profile: [p], certType: [root]}]\n", "profile p is for leaf, which certType excludes"},
	} {
		_, err := Parse([]byte("id: test\n" + test.policy))
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestParseFile_IncludedProfiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"base.yaml":  "id: base\nprofiles: [{id: subscriber, role: leaf}]\n",
		"child.yaml": "id: child\nincludes: [base.yaml]\nrules: [{id: r, target: certificate.version, operator: present, severity: error, profile: [subscriber]}]\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p, err := ParseFile(filepath.Join(dir, "child.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Profiles) != 1 || p.Profiles[0].ID != "subscriber" {
		t.Errorf("profiles = %+v, want the included subscriber profile", p.Profiles)
	}
}

func TestParse_GroupProfileDefault(t *testing.T) {
	p, err := Parse([]byte(`
id: test
profiles: [{id: subscriber, role: leaf}, {id: ca, role: intermediate}]
groups:
  - id: g
    profile: [subscriber]
    rules:
      - {id: inherits, target: certificate.version, operator: present, severity: error}
      - {id: overrides, target: certificate.version, operator: present, severity: error, profile: [ca]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Rules[0].Profile, ",") != "subscriber" || strings.Join(p.Rules[1].Profile, ",") != "ca" {
		t.Errorf("profiles = %v, %v", p.Rules[0].Profile, p.Rules[1].Profile)
	}
}
