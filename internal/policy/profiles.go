package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

// Profile is a kind of input that a standard sets requirements for, such as
// a subscriber certificate or a TLS subordinate CA. Each input is evaluated
// under at most one profile per policy: a profile the user assumed for it,
// or else the first profile of its role, in policy order, whose condition
// holds. An assumeOnly profile describes what the input cannot show, such as
// cross-certification, and is never inferred.
type Profile struct {
	ID         string          `yaml:"id"`
	Title      string          `yaml:"title,omitempty"`
	Reference  string          `yaml:"reference,omitempty"`
	Role       string          `yaml:"role"`
	When       *rule.Condition `yaml:"when,omitempty"`
	AssumeOnly bool            `yaml:"assumeOnly,omitempty"`
}

// Profile bases reported with a result.
const (
	ProfileInferred = "inferred"
	ProfileAssumed  = "assumed"
)

func validateProfiles(profiles []Profile) error {
	seen := make(map[string]struct{}, len(profiles))
	for i, profile := range profiles {
		if strings.TrimSpace(profile.ID) == "" {
			return fmt.Errorf("profile %d: id is required", i)
		}
		if err := rejectSurroundingWhitespace(fmt.Sprintf("profile %d id", i), profile.ID); err != nil {
			return err
		}
		if _, duplicate := seen[profile.ID]; duplicate {
			return fmt.Errorf("duplicate profile id %q", profile.ID)
		}
		seen[profile.ID] = struct{}{}
		field := "profile " + profile.ID
		if _, ok := validRuleCertTypes[profile.Role]; !ok {
			return fmt.Errorf("%s: role %q is not a rule role", field, profile.Role)
		}
		if profile.AssumeOnly && profile.When != nil {
			return fmt.Errorf("%s: an assumeOnly profile is never inferred and takes no when", field)
		}
		if profile.When != nil {
			if err := validateCondition(field+": when", *profile.When); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateProfileReferences checks that every rule names declared profiles
// whose roles agree with the rule's certType.
func validateProfileReferences(p Policy) error {
	roles := make(map[string]string, len(p.Profiles))
	for _, profile := range p.Profiles {
		roles[profile.ID] = profile.Role
	}
	for _, candidate := range p.Rules {
		seen := make(map[string]struct{}, len(candidate.Profile))
		for _, id := range candidate.Profile {
			if _, duplicate := seen[id]; duplicate {
				return fmt.Errorf("rule %s: duplicate profile %q", candidate.ID, id)
			}
			seen[id] = struct{}{}
			role, ok := roles[id]
			if !ok {
				return fmt.Errorf("rule %s: unknown profile %q", candidate.ID, id)
			}
			if len(candidate.CertType) > 0 && !slices.Contains(candidate.CertType, role) {
				return fmt.Errorf("rule %s: profile %s is for %s, which certType excludes", candidate.ID, id, role)
			}
		}
	}
	return nil
}

// selectedProfile is the profile an input is evaluated under; the zero
// value means no profile of the policy applies.
type selectedProfile struct {
	id, basis, role string
}

func (s selectedProfile) mismatch(profiles []string) string {
	want := strings.Join(profiles, ", ")
	if s.id == "" {
		return fmt.Sprintf("applies to profiles %s; no profile of the policy applies to this %s", want, s.role)
	}
	return fmt.Sprintf("applies to profiles %s; evaluated as %s (%s)", want, s.id, s.basis)
}

func selectProfile(
	p Policy,
	root *node.Node,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) selectedProfile {
	role := inputTypeFromContext(ctx)
	if ctx != nil && ctx.Input.Kind != "" {
		role = ctx.Input.Kind
	}
	none := selectedProfile{role: role}
	if len(p.Profiles) == 0 || ctx == nil {
		return none
	}
	for _, profile := range p.Profiles {
		if profile.Role == role && slices.Contains(ctx.AssumedProfiles, profile.ID) {
			return selectedProfile{id: profile.ID, basis: ProfileAssumed, role: role}
		}
	}
	for _, profile := range p.Profiles {
		if profile.Role != role || profile.AssumeOnly {
			continue
		}
		if profile.When != nil {
			holds, err := rule.ConditionHolds(root, profile.When, reg, ctx)
			if err != nil || !holds {
				continue
			}
		}
		return selectedProfile{id: profile.ID, basis: ProfileInferred, role: role}
	}
	return none
}
