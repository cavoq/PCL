package policy

import (
	"time"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

type Policy struct {
	ID        string      `yaml:"id"`
	Version   string      `yaml:"version"`
	Metadata  *Metadata   `yaml:"metadata,omitempty"`
	Includes  []string    `yaml:"includes,omitempty"`
	AppliesTo []string    `yaml:"appliesTo,omitempty"`
	CertType  []string    `yaml:"certType,omitempty"`
	CRLType   []string    `yaml:"crlType,omitempty"`
	TSTType   []string    `yaml:"tstType,omitempty"`
	SCTType   []string    `yaml:"sctType,omitempty"`
	Rules     []rule.Rule `yaml:"rules"`
	// Groups are expanded into Rules, after the policy's own rules, when the
	// policy is parsed; parsed policies carry no groups.
	Groups []Group `yaml:"groups,omitempty"`
}

// Metadata describes a policy pack. It does not select inputs, grant trust,
// initialize validation, or change rule evaluation. Includes merge rules only;
// the including policy keeps its own metadata.
type Metadata struct {
	Title       string   `yaml:"title,omitempty"`
	Standard    string   `yaml:"standard,omitempty"`
	Edition     string   `yaml:"edition,omitempty"`
	Source      string   `yaml:"source,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Inputs      []string `yaml:"inputs,omitempty"`
}

// Policy verdicts besides rule.VerdictPass, rule.VerdictFail and
// rule.VerdictInconclusive.
const (
	// VerdictNotApplicable: every rule was skipped as not applicable to the
	// input, so the policy decided nothing.
	VerdictNotApplicable = "not_applicable"
)

// Verdict decides a policy from its rule results: fail when an error rule
// failed, else inconclusive when an error rule lacked evidence, else
// not_applicable when no rule applied, else pass. Warning and info rules
// never fail a policy or make it inconclusive.
func Verdict(results []rule.Result) string {
	applied, inconclusive := false, false
	for _, result := range results {
		switch result.Verdict {
		case rule.VerdictFail:
			if result.Severity == rule.SeverityError {
				return rule.VerdictFail
			}
			applied = true
		case rule.VerdictInconclusive:
			inconclusive = inconclusive || result.Severity == rule.SeverityError
			applied = true
		case rule.VerdictPass:
			applied = true
		}
	}
	switch {
	case inconclusive:
		return rule.VerdictInconclusive
	case !applied:
		return VerdictNotApplicable
	default:
		return rule.VerdictPass
	}
}

type Result struct {
	PolicyID  string        `json:"policy_id" yaml:"policy_id"`
	CertType  string        `json:"cert_type" yaml:"cert_type"`
	CertPath  string        `json:"cert_path" yaml:"cert_path"`
	Source    string        `json:"source" yaml:"source"`
	Results   []rule.Result `json:"rules" yaml:"rules"`
	Verdict   string        `json:"verdict" yaml:"verdict"`
	CheckedAt time.Time     `json:"checked_at" yaml:"checked_at"`
}

func Evaluate(
	p Policy,
	root *node.Node,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) Result {
	inputType := inputTypeFromContext(ctx)
	results := make([]rule.Result, 0, len(p.Rules))

	for _, r := range p.Rules {
		if !RuleAppliesToInput(r, inputType) {
			results = append(results, rule.Skipped(r, rule.CodeInputType, "not applicable to input type "+inputType))
			continue
		}
		results = append(results, rule.Evaluate(root, r, reg, ctx))
	}

	var input operator.Input
	if ctx != nil {
		input = ctx.Input
	}

	return Result{
		PolicyID:  p.ID,
		CertType:  input.Kind,
		CertPath:  input.Path,
		Source:    input.Source.String(),
		Results:   results,
		Verdict:   Verdict(results),
		CheckedAt: time.Now(),
	}
}
