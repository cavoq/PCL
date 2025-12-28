package operator

import (
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
)

type EvaluationContext struct {
	Root  *node.Node
	Now   time.Time
	Cert  *cert.Info
	Chain []*cert.Info
	CRLs  []*crl.Info
	OCSPs []*ocsp.Info
}

type ContextOption func(*EvaluationContext)

func WithCRLs(crls []*crl.Info) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.CRLs = crls
	}
}

func WithOCSPs(ocsps []*ocsp.Info) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.OCSPs = ocsps
	}
}

func NewEvaluationContext(root *node.Node, c *cert.Info, chain []*cert.Info, opts ...ContextOption) *EvaluationContext {
	ctx := &EvaluationContext{
		Root:  root,
		Now:   time.Now(),
		Cert:  c,
		Chain: chain,
	}
	for _, opt := range opts {
		opt(ctx)
	}
	return ctx
}
