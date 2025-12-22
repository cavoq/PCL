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
	PolicyID  string
	CertType  string
	Results   []rule.Result
	Verdict   string
	CheckedAt time.Time
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

		if !res.Passed && r.Severity == "error" {
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
