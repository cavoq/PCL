package operator

import (
	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	ocsppkg "github.com/cavoq/PCL/internal/ocsp"
)

type OCSPValid struct{}

func (OCSPValid) Name() string { return "ocspValid" }

func (OCSPValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	assessment, err := applicableOCSP(ctx)
	return err == nil && assessment.Valid(), err
}

type NotRevokedOCSP struct{}

func (NotRevokedOCSP) Name() string { return "notRevokedOCSP" }

func (NotRevokedOCSP) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	assessment, err := applicableOCSP(ctx)
	return err == nil && assessment.Status() == ocsppkg.StatusGood, err
}

type OCSPGood struct{}

func (OCSPGood) Name() string { return "ocspGood" }

func (OCSPGood) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	assessment, err := applicableOCSP(ctx)
	return err == nil && assessment.HasGood(), err
}

// applicableOCSP returns the certificate's OCSP assessment, or a
// NoEvidenceError when no supplied response applies to the certificate.
func applicableOCSP(ctx *EvaluationContext) (ocsppkg.Assessment, error) {
	if ctx == nil || !ctx.HasCert() {
		return ocsppkg.Assessment{}, nil
	}
	assessment := assessOCSP(ctx)
	if assessment.Status() == ocsppkg.StatusNotApplicable {
		return assessment, NoEvidenceError{Evidence: "OCSP response"}
	}
	return assessment, nil
}

func assessOCSP(ctx *EvaluationContext) ocsppkg.Assessment {
	if ctx == nil || !ctx.HasCert() {
		return ocsppkg.Assessment{}
	}
	if ctx.OCSPAssessment != nil {
		return *ctx.OCSPAssessment
	}
	return ocsppkg.AssessCertificate(ctx.Cert.Cert, ctx.OCSPs, cert.CertsFromInfos(ctx.Chain), ctx.Now)
}
