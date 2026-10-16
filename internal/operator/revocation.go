package operator

import (
	crlpkg "github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	ocsppkg "github.com/cavoq/PCL/internal/ocsp"
)

// NotRevokedByAvailableEvidence combines the certificate-scoped CRL and OCSP
// decisions already prepared by the evaluator. Revoked evidence wins over
// Good evidence; otherwise at least one mechanism must establish Good. This
// lets profiles that permit either CRL or OCSP evidence fail closed without
// choosing a mechanism from certificate syntax alone. Without any applicable
// CRL or OCSP evidence the decision is inconclusive.
type NotRevokedByAvailableEvidence struct{}

func (NotRevokedByAvailableEvidence) Name() string { return "notRevokedByAvailableEvidence" }

func (NotRevokedByAvailableEvidence) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if ctx == nil || !ctx.HasCert() {
		return false, nil
	}

	crls := crlpkg.Assessment{}
	if ctx.CRLAssessment != nil {
		crls = *ctx.CRLAssessment
	}
	crlStatus := crls.Status()
	ocspStatus := assessOCSP(ctx).Status()

	if crlStatus == crlpkg.RevocationRevoked || ocspStatus == ocsppkg.StatusRevoked {
		return false, nil
	}
	if crlStatus == crlpkg.RevocationGood || ocspStatus == ocsppkg.StatusGood {
		return true, nil
	}
	if !crls.HasApplicableEvidence() && ocspStatus == ocsppkg.StatusNotApplicable {
		return false, NoEvidenceError{Evidence: "CRL or OCSP response"}
	}
	return false, nil
}
