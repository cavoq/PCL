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
	Includes  []string    `yaml:"includes,omitempty"`
	AppliesTo []string    `yaml:"appliesTo,omitempty"`
	CertType  []string    `yaml:"certType,omitempty"`
	CRLType   []string    `yaml:"crlType,omitempty"`
	TSTType   []string    `yaml:"tstType,omitempty"`
	SCTType   []string    `yaml:"sctType,omitempty"`
	Rules     []rule.Rule `yaml:"rules"`
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
	verdict := rule.VerdictPass

	for _, r := range p.Rules {
		if !RuleAppliesToInput(r, inputType) {
			results = append(results, rule.Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   rule.VerdictSkip,
				Severity:  r.Severity,
				Details:   "not applicable to input type " + inputType,
			})
			continue
		}

		res := rule.Evaluate(root, r, reg, ctx)
		results = append(results, res)

		if res.Verdict == rule.VerdictFail && r.Severity == rule.SeverityError {
			verdict = rule.VerdictFail
		}
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
		Verdict:   verdict,
		CheckedAt: time.Now(),
	}
}
