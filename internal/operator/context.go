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

// IsCACRL checks if the CRL issuer is a CA certificate in the chain.
// Returns true if the CRL was issued by a Root or Intermediate CA.
func (ctx *EvaluationContext) IsCACRL(crlInfo *crl.Info) bool {
	if ctx == nil || crlInfo == nil || crlInfo.CRL == nil {
		return false
	}

	if !ctx.HasChain() {
		return false
	}

	crlIssuer := crlInfo.CRL.Issuer.String()

	for _, certInfo := range ctx.Chain {
		if certInfo.Cert == nil {
			continue
		}
		if certInfo.Cert.Subject.String() == crlIssuer {
			// Check if this issuer is a CA
			if certInfo.Cert.IsCA {
				return true
			}
		}
	}

	return false
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
