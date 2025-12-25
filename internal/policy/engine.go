package policy

import (
	"time"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

type Policy struct {
	ID      string      `yaml:"id"`
	Version string      `yaml:"version"`
	Rules   []rule.Rule `yaml:"rules"`
}

type Result struct {
	PolicyID  string        `json:"policy_id" yaml:"policy_id"`
	CertType  string        `json:"cert_type" yaml:"cert_type"`
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
	results := make([]rule.Result, 0, len(p.Rules))
	verdict := "pass"

	for _, r := range p.Rules {
		res := rule.Evaluate(root, r, reg, ctx)
		results = append(results, res)

		if res.Verdict == rule.VerdictFail && r.Severity == "error" {
			verdict = "fail"
		}
	}

	certType := ""
	if ctx != nil && ctx.Cert != nil {
		certType = ctx.Cert.Type
	}

	return Result{
		PolicyID:  p.ID,
		CertType:  certType,
		Results:   results,
		Verdict:   verdict,
		CheckedAt: time.Now(),
	}
}
