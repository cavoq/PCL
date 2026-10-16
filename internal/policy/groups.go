package policy

import (
	"fmt"
	"strings"

	"github.com/cavoq/PCL/internal/rule"
)

// Group collects the rules of one section of a source, such as one clause,
// and states the fields they share. A rule's own reference, requirement,
// certType, profile or effective window replaces the group's; a group condition is
// combined with the rule's own, and both must hold.
type Group struct {
	ID          string          `yaml:"id"`
	Title       string          `yaml:"title,omitempty"`
	Reference   string          `yaml:"reference,omitempty"`
	Requirement string          `yaml:"requirement,omitempty"`
	CertType    []string        `yaml:"certType,omitempty"`
	Profile     []string        `yaml:"profile,omitempty"`
	Effective   *rule.Effective `yaml:"effective,omitempty"`
	When        *rule.Condition `yaml:"when,omitempty"`
	Rules       []rule.Rule     `yaml:"rules"`
}

// expandGroups appends the rules of every group, with the group's fields
// applied, to the policy's own rules and removes the groups.
func expandGroups(p Policy) (Policy, error) {
	if len(p.Groups) == 0 {
		return p, nil
	}
	seen := make(map[string]struct{}, len(p.Groups))
	rules := append([]rule.Rule(nil), p.Rules...)
	for i, group := range p.Groups {
		if err := validateGroup(i, group, seen); err != nil {
			return Policy{}, err
		}
		for _, candidate := range group.Rules {
			rules = append(rules, applyGroup(group, candidate))
		}
	}
	p.Rules, p.Groups = rules, nil
	return p, nil
}

func validateGroup(index int, group Group, seen map[string]struct{}) error {
	if strings.TrimSpace(group.ID) == "" {
		return fmt.Errorf("group %d: id is required", index)
	}
	if err := rejectSurroundingWhitespace(fmt.Sprintf("group %d id", index), group.ID); err != nil {
		return err
	}
	if _, duplicate := seen[group.ID]; duplicate {
		return fmt.Errorf("duplicate group id %q", group.ID)
	}
	seen[group.ID] = struct{}{}
	field := "group " + group.ID
	if len(group.Rules) == 0 {
		return fmt.Errorf("%s: rules are required", field)
	}
	if group.Requirement != "" {
		if _, ok := validRequirements[group.Requirement]; !ok {
			return fmt.Errorf("%s: invalid requirement %q: use must, should or may", field, group.Requirement)
		}
	}
	if err := validateValues(field+" certType", group.CertType, validRuleCertTypes); err != nil {
		return err
	}
	if group.Effective != nil {
		if err := validateEffective(rule.Rule{ID: field, Effective: group.Effective}); err != nil {
			return err
		}
	}
	if group.When != nil {
		return validateCondition(field+": when", *group.When)
	}
	return nil
}

func applyGroup(group Group, candidate rule.Rule) rule.Rule {
	if candidate.Reference == "" {
		candidate.Reference = group.Reference
	}
	if candidate.Requirement == "" {
		candidate.Requirement = group.Requirement
	}
	if candidate.CertType == nil {
		candidate.CertType = group.CertType
	}
	if candidate.Profile == nil {
		candidate.Profile = group.Profile
	}
	if candidate.Effective == nil {
		candidate.Effective = group.Effective
	}
	switch {
	case group.When == nil:
	case candidate.When == nil:
		candidate.When = group.When
	default:
		candidate.When = &rule.Condition{AllOf: []rule.Condition{*group.When, *candidate.When}}
	}
	return candidate
}
