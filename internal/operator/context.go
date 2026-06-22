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

func (ctx *EvaluationContext) HasCert() bool {
	return ctx != nil && ctx.Cert != nil && ctx.Cert.Cert != nil
}

func (ctx *EvaluationContext) HasChain() bool {
	return ctx != nil && len(ctx.Chain) > 0
}

func (ctx *EvaluationContext) HasCRLs() bool {
	return ctx != nil && len(ctx.CRLs) > 0
}

func (ctx *EvaluationContext) HasOCSPs() bool {
	return ctx != nil && len(ctx.OCSPs) > 0
}

// IsCACRL mirrors the crl.isCACRL policy node (signer in chain pool + validity inference).
func (ctx *EvaluationContext) IsCACRL(crlInfo *crl.Info) bool {
	if ctx == nil || crlInfo == nil || crlInfo.CRL == nil {
		return false
	}
	return crl.IsCACRL(crlInfo.CRL, cert.CertsFromInfos(ctx.Chain))
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
