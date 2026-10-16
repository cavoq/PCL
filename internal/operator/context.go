package operator

import (
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	pathpkg "github.com/cavoq/PCL/internal/path"
	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

// Kinds of evaluated inputs other than certificates, whose kinds are their
// roles (cert.TypeRoot, cert.TypeIntermediate, cert.TypeLeaf and
// cert.TypeOCSPSigning).
const (
	KindCRL  = "crl"
	KindOCSP = "ocsp"
)

// Input identifies the evaluated input for rule filters and results.
type Input struct {
	// Kind is a certificate's role, KindCRL or KindOCSP.
	Kind   string
	Path   string
	Source source.Info
}

type EvaluationContext struct {
	Root *node.Node
	Now  time.Time
	// Input identifies the evaluated input. Cert is set only when it is a
	// certificate.
	Input Input
	// AssumedProfiles names policy profiles the user assumed for this input,
	// such as a cross-certified CA, which its content cannot show.
	AssumedProfiles []string
	Cert            *cert.Info
	Chain           []*cert.Info
	CRLs            []*crl.Info
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

	// CertificatePolicyInputs are the RFC 5280 Section 6.1 inputs supplied by
	// the caller. When unconfigured, certificatePolicyValid retains its legacy
	// operand-based behavior.
	CertificatePolicyInputs CertificatePolicyInputs

	// PathValidation is the single path-domain decision for the evaluated target
	// certificate. It is nil for profile-only runs and non-target certificates.
	PathValidation *pathpkg.Result
}

func (ctx *EvaluationContext) HasCert() bool {
	return ctx != nil && ctx.Cert != nil && ctx.Cert.Cert != nil
}

// ChainPosition returns the position of the evaluated certificate in
// Chain.
func (ctx *EvaluationContext) ChainPosition() (int, bool) {
	if !ctx.HasCert() {
		return 0, false
	}
	return cert.ChainIndex(ctx.Cert, ctx.Chain)
}

// ChainIssuer returns the certificate after the evaluated one in Chain,
// which issued it.
func (ctx *EvaluationContext) ChainIssuer() (*x509.Certificate, bool) {
	position, ok := ctx.ChainPosition()
	if !ok || position+1 >= len(ctx.Chain) {
		return nil, false
	}
	issuer := ctx.Chain[position+1]
	if issuer == nil || issuer.Cert == nil {
		return nil, false
	}
	return issuer.Cert, true
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

func WithCertificatePolicyInputs(inputs CertificatePolicyInputs) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.CertificatePolicyInputs = inputs
	}
}

func WithPathValidation(result *pathpkg.Result) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.PathValidation = result
	}
}

// WithInput identifies an input that is not a certificate.
func WithInput(input Input) ContextOption {
	return func(ctx *EvaluationContext) {
		ctx.Input = input
	}
}

// NewEvaluationContext creates the context for evaluating root. For a
// certificate c, the input kind is its role.
func NewEvaluationContext(root *node.Node, c *cert.Info, chain []*cert.Info, opts ...ContextOption) *EvaluationContext {
	ctx := &EvaluationContext{
		Root:  root,
		Now:   time.Now(),
		Cert:  c,
		Chain: chain,
	}
	if c != nil {
		ctx.Input = Input{Kind: cert.GetCertType(c.Cert), Path: c.FilePath, Source: c.Source}
	}
	for _, opt := range opts {
		opt(ctx)
	}
	return ctx
}
