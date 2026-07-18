package operator

import (
	"time"

	crlpkg "github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
)

type CRLValid struct{}

func (CRLValid) Name() string { return "crlValid" }

func (CRLValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	return profileCRLsSatisfy(ctx, crlpkg.IsCurrentAt), nil
}

type CRLNotExpired struct{}

func (CRLNotExpired) Name() string { return "crlNotExpired" }

func (CRLNotExpired) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	return profileCRLsSatisfy(ctx, crlpkg.IsNotExpiredAt), nil
}

func profileCRLsSatisfy(ctx *EvaluationContext, predicate func(*x509.RevocationList, time.Time) bool) bool {
	if ctx == nil {
		return false
	}

	sawCRL := false
	for _, crlInfo := range ctx.ProfileCRLs() {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}
		sawCRL = true
		if !predicate(crlInfo.CRL, ctx.Now) {
			return false
		}
	}

	return sawCRL
}

type CRLSignedBy struct{}

func (CRLSignedBy) Name() string { return "crlSignedBy" }

func (CRLSignedBy) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil {
		return false, nil
	}

	issuerPool := ctx.CRLIssuerPool()
	if len(issuerPool) == 0 {
		return false, nil
	}

	sawCRL := false
	for _, crlInfo := range ctx.ProfileCRLs() {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}
		sawCRL = true
		crl := crlInfo.CRL

		signer := crlpkg.VerifyingCertFromPool(crl, issuerPool)
		if signer == nil {
			return false, nil
		}
	}

	return sawCRL, nil
}

type NotRevoked struct{}

func (NotRevoked) Name() string { return "notRevoked" }

func (NotRevoked) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	lists := make([]*x509.RevocationList, 0, len(ctx.CRLs))
	for _, crlInfo := range ctx.CRLs {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}
		lists = append(lists, crlInfo.CRL)
	}

	statusCtx := crlpkg.RevocationContext{
		Now:     ctx.Now,
		Issuers: ctx.CRLIssuerPool(),
	}
	return crlpkg.StatusForCertificate(ctx.Cert.Cert, lists, statusCtx) == crlpkg.RevocationGood, nil
}
