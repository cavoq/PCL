package operator

import (
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/zmap/zcrypto/x509"
)

type EvaluationContext struct {
	Root  *node.Node
	Now   time.Time
	Cert  *cert.Info
	Chain []*cert.Info
	CRLs  []*crl.Info
	// CRLAssessment is the single domain decision projected for Cert. Keeping
	// it on the evaluation context lets policy adapters consume the same
	// assessment without rerunning revocation processing.
	CRLAssessment *crl.Assessment
	CurrentCRL    *crl.Info
	CRLIssuers    []*x509.Certificate
	OCSPs         []*ocsp.Info
	// OCSPAssessment is the target-scoped domain decision shared by every OCSP
	// policy adapter for Cert. A non-nil pointer is authoritative even when the
	// assessment contains no applicable evidence.
	OCSPAssessment *ocsp.Assessment

	// ApplicationPurpose is an optional friendly EKU name or dotted EKU OID
	// supplied by the caller for certificate-purpose evaluation.
	ApplicationPurpose string
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

func WithCurrentCRL(current *crl.Info) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.CurrentCRL = current
	}
}

func WithCRLAssessment(assessment *crl.Assessment) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.CRLAssessment = assessment
	}
}

func WithEvaluationTime(now time.Time) ContextOption {
	return func(ctx *EvaluationContext) {
		if !now.IsZero() {
			ctx.Now = now
		}
	}
}

func (ctx *EvaluationContext) ProfileCRLs() []*crl.Info {
	if ctx == nil {
		return nil
	}
	if ctx.CurrentCRL != nil {
		return []*crl.Info{ctx.CurrentCRL}
	}
	return ctx.CRLs
}

func WithCRLIssuers(issuers []*x509.Certificate) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.CRLIssuers = issuers
	}
}

func (ctx *EvaluationContext) CRLIssuerPool() []*x509.Certificate {
	if ctx == nil {
		return nil
	}
	if len(ctx.CRLIssuers) > 0 {
		return ctx.CRLIssuers
	}
	return cert.CertsFromInfos(ctx.Chain)
}

func WithOCSPs(ocsps []*ocsp.Info) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.OCSPs = ocsps
	}
}

func WithOCSPAssessment(assessment *ocsp.Assessment) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.OCSPAssessment = assessment
	}
}

func WithApplicationPurpose(purpose string) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.ApplicationPurpose = purpose
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
