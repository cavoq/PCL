package operator

import (
	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	ocsppkg "github.com/cavoq/PCL/internal/ocsp"
)

type OCSPValid struct{}

func (OCSPValid) Name() string { return "ocspValid" }

func (OCSPValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	return assessOCSP(ctx).Valid(), nil
}

type NotRevokedOCSP struct{}

func (NotRevokedOCSP) Name() string { return "notRevokedOCSP" }

func (NotRevokedOCSP) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	return assessOCSP(ctx).Status() == ocsppkg.StatusGood, nil
}

type OCSPGood struct{}

func (OCSPGood) Name() string { return "ocspGood" }

func (OCSPGood) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	return assessOCSP(ctx).HasGood(), nil
}

func assessOCSP(ctx *EvaluationContext) ocsppkg.Assessment {
	if ctx == nil || !ctx.HasCert() {
		return ocsppkg.Assessment{}
	}
	return ocsppkg.AssessCertificate(ctx.Cert.Cert, ctx.OCSPs, cert.CertsFromInfos(ctx.Chain), ctx.Now)
}
