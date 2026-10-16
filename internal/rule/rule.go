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

type Condition struct {
	Target   string `yaml:"target"`
	Operator string `yaml:"operator"`
	Operands any    `yaml:"operands"` // Can be []any or map[string]any
}

type Rule struct {
	ID        string `yaml:"id"`
	Reference string `yaml:"reference,omitempty"`
	Target    string `yaml:"target"`
	Operator  string `yaml:"operator"`
	Operands  any    `yaml:"operands"` // Can be []any or map[string]any
	// Requirement is the source's requirement level; it supplies Severity
	// when the policy omits it.
	Requirement string     `yaml:"requirement,omitempty"`
	Severity    string     `yaml:"severity"`
	Message     string     `yaml:"message,omitempty"`
	CertType    []string   `yaml:"certType,omitempty"`
	When        *Condition `yaml:"when,omitempty"`
}
