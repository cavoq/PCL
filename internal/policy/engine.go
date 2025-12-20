package policy

import (
	"time"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

type Policy struct {
	ID    string      `yaml:"id"`
	Rules []rule.Rule `yaml:"rules"`
}

type Result struct {
	PolicyID  string
	Results   []rule.Result
	Verdict   string
	CheckedAt time.Time
}

func Evaluate(
	p Policy,
	root *node.Node,
	reg *operator.Registry,
) Result {

	results := make([]rule.Result, 0, len(p.Rules))
	verdict := "pass"

	for _, r := range p.Rules {
		res := rule.Evaluate(root, r, reg)
		results = append(results, res)

		if !res.Passed && r.Severity == "error" {
			verdict = "fail"
		}
	}

	return Result{
		PolicyID:  p.ID,
		Results:   results,
		Verdict:   verdict,
		CheckedAt: time.Now(),
	}
}
