package operator

import (
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
)

type EvaluationContext struct {
	Root  *node.Node
	Now   time.Time
	Cert  *cert.Info
	Chain []*cert.Info
}

func NewEvaluationContext(root *node.Node, c *cert.Info, chain []*cert.Info) *EvaluationContext {
	return &EvaluationContext{
		Root:  root,
		Now:   time.Now(),
		Cert:  c,
		Chain: chain,
	}
}
