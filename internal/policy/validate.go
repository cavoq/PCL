package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/rule"
)

var (
	validInputTypes = stringSet(
		InputCert,
		InputCRL,
		InputOCSP,
		InputTST,
		InputSCT,
		InputAttrCert,
	)
	validPolicyCertTypes = stringSet(
		"ca",
		"root",
		"intermediate",
		"leaf",
		"serverAuth",
		"clientAuth",
		"codeSigning",
		"emailProtection",
		"timeStamping",
		"ocspSigning",
	)
	validRuleCertTypes = stringSet(
		"root",
		"intermediate",
		"leaf",
		"ocspSigning",
		InputCRL,
		InputOCSP,
		InputTST,
		InputSCT,
		InputAttrCert,
	)
	validCRLTypes = stringSet(
		"completeCRL",
		"indirectCRL",
		"deltaCRLIndicator",
		oid.DeltaCRLIndicator,
	)
	validSeverities = stringSet(
		rule.SeverityError,
		rule.SeverityWarning,
		rule.SeverityInfo,
	)
)

func validatePolicy(p Policy) error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("policy id is required")
	}
	if err := rejectSurroundingWhitespace("policy id", p.ID); err != nil {
		return err
	}

	if err := validateIncludes(p.Includes); err != nil {
		return err
	}
	if err := validateValues("appliesTo", p.AppliesTo, validInputTypes); err != nil {
		return err
	}
	if err := validateCertTypes("certType", p.CertType, validPolicyCertTypes); err != nil {
		return err
	}
	if err := validateValues("crlType", p.CRLType, validCRLTypes); err != nil {
		return err
	}

	seenRuleIDs := make(map[string]struct{}, len(p.Rules))
	for i, candidate := range p.Rules {
		if err := validateRule(i, candidate, seenRuleIDs); err != nil {
			return err
		}
	}
	return nil
}

func validateIncludes(includes []string) error {
	seen := make(map[string]struct{}, len(includes))
	for i, include := range includes {
		trimmed := strings.TrimSpace(include)
		if trimmed == "" {
			return fmt.Errorf("include %d: path is required", i)
		}
		if err := rejectSurroundingWhitespace(fmt.Sprintf("include %d path", i), include); err != nil {
			return err
		}
		normalized := filepath.Clean(trimmed)
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("duplicate include path %q", include)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

func validateRule(index int, candidate rule.Rule, seenIDs map[string]struct{}) error {
	id := strings.TrimSpace(candidate.ID)
	if id == "" {
		return fmt.Errorf("rule %d: id is required", index)
	}
	if err := rejectSurroundingWhitespace(fmt.Sprintf("rule %d id", index), candidate.ID); err != nil {
		return err
	}
	if _, duplicate := seenIDs[id]; duplicate {
		return fmt.Errorf("duplicate rule id %q", id)
	}
	seenIDs[id] = struct{}{}

	if strings.TrimSpace(candidate.Target) == "" {
		return fmt.Errorf("rule %s: target is required", candidate.ID)
	}
	if err := rejectSurroundingWhitespace("rule "+candidate.ID+" target", candidate.Target); err != nil {
		return err
	}
	if strings.TrimSpace(candidate.Operator) == "" {
		return fmt.Errorf("rule %s: operator is required", candidate.ID)
	}
	if err := rejectSurroundingWhitespace("rule "+candidate.ID+" operator", candidate.Operator); err != nil {
		return err
	}
	if err := validateSeverity(candidate); err != nil {
		return err
	}
	if err := validateValues("rule "+candidate.ID+" certType", candidate.CertType, validRuleCertTypes); err != nil {
		return err
	}

	if candidate.When == nil {
		return nil
	}
	if strings.TrimSpace(candidate.When.Target) == "" {
		return fmt.Errorf("rule %s: when.target is required", candidate.ID)
	}
	if err := rejectSurroundingWhitespace("rule "+candidate.ID+" when.target", candidate.When.Target); err != nil {
		return err
	}
	if strings.TrimSpace(candidate.When.Operator) == "" {
		return fmt.Errorf("rule %s: when.operator is required", candidate.ID)
	}
	if err := rejectSurroundingWhitespace("rule "+candidate.ID+" when.operator", candidate.When.Operator); err != nil {
		return err
	}
	return nil
}

func validateSeverity(candidate rule.Rule) error {
	severity := strings.TrimSpace(candidate.Severity)
	if severity == "" {
		return fmt.Errorf("rule %s: severity is required", candidate.ID)
	}
	if err := rejectSurroundingWhitespace("rule "+candidate.ID+" severity", candidate.Severity); err != nil {
		return err
	}
	if _, ok := validSeverities[severity]; !ok {
		return fmt.Errorf("rule %s: invalid severity %q", candidate.ID, candidate.Severity)
	}
	return nil
}

func validateValues(field string, values []string, allowed map[string]struct{}) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if err := rejectSurroundingWhitespace(field+" value", value); err != nil {
			return err
		}
		if _, ok := allowed[trimmed]; !ok {
			return fmt.Errorf("%s contains unsupported value %q", field, value)
		}
		if _, duplicate := seen[trimmed]; duplicate {
			return fmt.Errorf("%s contains duplicate value %q", field, value)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

func validateCertTypes(field string, values []string, allowed map[string]struct{}) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if err := rejectSurroundingWhitespace(field+" value", value); err != nil {
			return err
		}
		_, knownRole := allowed[trimmed]
		if !knownRole && !oid.ValidDotted(trimmed) {
			return fmt.Errorf("%s contains unsupported value %q", field, value)
		}
		if _, duplicate := seen[trimmed]; duplicate {
			return fmt.Errorf("%s contains duplicate value %q", field, value)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

func rejectSurroundingWhitespace(field, value string) error {
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", field)
	}
	return nil
}

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
