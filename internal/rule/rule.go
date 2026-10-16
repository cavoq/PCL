// Package rule provides rule types and verdict constants.
package rule

const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// Requirement levels (RFC 2119) state how strongly the source requires what a
// rule checks: MUST and SHALL (and their negations), SHOULD and RECOMMENDED,
// MAY and OPTIONAL.
const (
	RequirementMust   = "must"
	RequirementShould = "should"
	RequirementMay    = "may"
)

// DefaultSeverity returns the severity of a rule that states only its
// requirement level: error for must, warning for should, info for may.
func DefaultSeverity(requirement string) string {
	switch requirement {
	case RequirementMust:
		return SeverityError
	case RequirementShould:
		return SeverityWarning
	case RequirementMay:
		return SeverityInfo
	default:
		return ""
	}
}

// Condition is a rule precondition: either one check of a target with an
// operator, or exactly one of AllOf, AnyOf and Not over nested conditions.
type Condition struct {
	Target   string `yaml:"target,omitempty"`
	Operator string `yaml:"operator,omitempty"`
	Operands any    `yaml:"operands,omitempty"` // Can be []any or map[string]any

	AllOf []Condition `yaml:"allOf,omitempty"`
	AnyOf []Condition `yaml:"anyOf,omitempty"`
	Not   *Condition  `yaml:"not,omitempty"`
}

type Rule struct {
	ID        string `yaml:"id"`
	Reference string `yaml:"reference,omitempty"`
	Target    string `yaml:"target"`
	Operator  string `yaml:"operator"`
	Operands  any    `yaml:"operands"` // Can be []any or map[string]any
	// Requirement is the source's requirement level; it supplies Severity
	// when the policy omits it.
	Requirement string   `yaml:"requirement,omitempty"`
	Severity    string   `yaml:"severity"`
	Message     string   `yaml:"message,omitempty"`
	CertType    []string `yaml:"certType,omitempty"`
	// Profile limits the rule to inputs evaluated under one of these
	// profiles of its policy.
	Profile []string `yaml:"profile,omitempty"`
	// Effective limits the rule to inputs issued, or evaluated, within a
	// window.
	Effective *Effective `yaml:"effective,omitempty"`
	When      *Condition `yaml:"when,omitempty"`
}
