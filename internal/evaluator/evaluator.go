// Package evaluator provides certificate evaluation against policies.
package evaluator

import (
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

// Context contains all data needed for policy evaluation.
type Context struct {
	Policies []policy.Policy
	Registry *operator.Registry
	CRLs     []*crl.Info
	OCSPs    []*ocsp.Info
	Chain    []*cert.Info

	// CRL issuer discovery for isCACRL (optional). When set, PCL may fetch CA
	// Issuers URLs from the chain to locate the CRL signing certificate.
	CRLResolveTimeout  time.Duration
	CRLResolveMaxDepth int
	CRLResolveWarn     io.Writer

	crlIssuerPools map[*crl.Info][]*x509.Certificate
}

func Chain(ctx Context) []policy.Result {
	ctx = PrepareCRLIssuers(ctx)
	var results []policy.Result
	var embeddedCRL *crl.Info
	var embeddedCRLIssuers []*x509.Certificate
	for _, crlInfo := range ctx.CRLs {
		if crlInfo != nil && crlInfo.CRL != nil {
			embeddedCRL = crlInfo
			embeddedCRLIssuers = ctx.crlIssuerPools[crlInfo]
			break
		}
	}
	allCRLIssuers := combinedCRLIssuerPool(ctx)

	for _, c := range ctx.Chain {
		tree := certzcrypto.BuildTree(c.Cert)

		if c.Source.Format != "" && c.Source.Type != source.Local {
			tree.Children["downloadFormat"] = node.New("downloadFormat", c.Source.Format)
			tree.Children["downloadURL"] = node.New("downloadURL", c.Source.URL)
		}

		if embeddedCRL != nil {
			crlNode := crl.BuildTreeWithChain(embeddedCRL.CRL, embeddedCRLIssuers)
			if crlNode != nil {
				tree.Children["crl"] = crlNode
			}
		}

		evalOpts := []operator.ContextOption{
			operator.WithCRLs(ctx.CRLs),
			operator.WithOCSPs(ctx.OCSPs),
		}
		if embeddedCRL != nil {
			evalOpts = append(evalOpts,
				operator.WithCurrentCRL(embeddedCRL),
				operator.WithCRLIssuers(allCRLIssuers),
			)
		}
		evalCtx := operator.NewEvaluationContext(tree, c, ctx.Chain, evalOpts...)

		filteredPolicies := policy.ByCertificate(ctx.Policies, c.Cert)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}
	}

	return results
}

func OCSP(ctx Context) []policy.Result {
	var results []policy.Result

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}

		ocspNode := ocspzcrypto.BuildTree(ocspInfo.Response)
		if ocspNode == nil {
			continue
		}

		ocspCertInfo := &cert.Info{
			FilePath: ocspInfo.FilePath,
			Type:     "ocsp",
			Source:   ocspInfo.Source,
		}

		tree := ocspNode
		evalOpts := []operator.ContextOption{operator.WithOCSPs(ctx.OCSPs)}
		evalCtx := operator.NewEvaluationContext(tree, ocspCertInfo, ctx.Chain, evalOpts...)

		filteredPolicies := policy.ByInput(ctx.Policies, policy.InputOCSP)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}

		if ocspInfo.Response.Certificate != nil {
			results = append(results, ocspSigningCert(ctx, ocspInfo)...)
		}
	}

	return results
}

func CRL(ctx Context) []policy.Result {
	ctx = PrepareCRLIssuers(ctx)
	var results []policy.Result

	for _, crlInfo := range ctx.CRLs {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}

		issuerCerts := ctx.crlIssuerPools[crlInfo]

		crlNode := crl.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
		if crlNode == nil {
			continue
		}

		crlCertInfo := &cert.Info{
			FilePath: crlInfo.FilePath,
			Type:     "crl",
			Source:   crlInfo.Source,
		}

		tree := crlNode
		evalOpts := []operator.ContextOption{
			operator.WithCRLs(ctx.CRLs),
			operator.WithCurrentCRL(crlInfo),
			operator.WithCRLIssuers(issuerCerts),
		}
		evalCtx := operator.NewEvaluationContext(tree, crlCertInfo, ctx.Chain, evalOpts...)

		filteredPolicies := policy.ByCRL(ctx.Policies, crlInfo.CRL)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}
	}

	return results
}

func CRLOnly(policies []policy.Policy, registry *operator.Registry, crls []*crl.Info, issuers []*cert.Info) []policy.Result {
	return CRL(Context{
		Policies: policies,
		Registry: registry,
		CRLs:     crls,
		Chain:    issuers,
	})
}

func OCSPOnly(policies []policy.Policy, registry *operator.Registry, ocsps []*ocsp.Info) []policy.Result {
	return OCSP(Context{
		Policies: policies,
		Registry: registry,
		OCSPs:    ocsps,
	})
}

func ocspSigningCert(ctx Context, ocspInfo *ocsp.Info) []policy.Result {
	zcryptoSignerCert, err := zcrypto.FromStdCert(ocspInfo.Response.Certificate)
	if err != nil || zcryptoSignerCert == nil {
		return nil
	}

	ocspSignerTree := certzcrypto.BuildTree(zcryptoSignerCert)
	ocspSignerInfo := &cert.Info{
		Cert:     zcryptoSignerCert,
		FilePath: ocspInfo.FilePath + " (signing cert)",
		Type:     "ocspSigning",
		Source:   source.Info{Type: source.Extracted, Description: "extracted from OCSP response"},
	}

	signerChain := ocsp.BuildSignerEvalChain(
		zcryptoSignerCert,
		ocspSignerInfo,
		ctx.Chain,
		ctx.CRLResolveTimeout,
		ctx.CRLResolveMaxDepth,
		ctx.CRLResolveWarn,
	)

	evalOpts := []operator.ContextOption{operator.WithOCSPs(ctx.OCSPs)}
	evalCtx := operator.NewEvaluationContext(ocspSignerTree, ocspSignerInfo, signerChain, evalOpts...)

	var results []policy.Result
	signerPolicies := policy.ByCertificate(ctx.Policies, zcryptoSignerCert)
	for _, p := range signerPolicies {
		res := policy.Evaluate(p, ocspSignerTree, ctx.Registry, evalCtx)
		results = append(results, res)
	}

	return results
}

func issuerCertsForCRL(ctx Context, revocationList *x509.RevocationList) []*x509.Certificate {
	if ctx.CRLResolveTimeout > 0 && ctx.CRLResolveMaxDepth > 0 {
		return crl.ResolveIssuerCerts(
			ctx.Chain,
			revocationList,
			ctx.CRLResolveTimeout,
			ctx.CRLResolveMaxDepth,
			ctx.CRLResolveWarn,
		)
	}
	return cert.CertsFromInfos(ctx.Chain)
}

// PrepareCRLIssuers resolves each CRL issuer once and stores the pools on the
// evaluation context. Passing the returned context to Chain and CRL makes
// certificate revocation and CRL-profile checks consume identical evidence.
func PrepareCRLIssuers(ctx Context) Context {
	if ctx.crlIssuerPools != nil {
		return ctx
	}

	ctx.crlIssuerPools = make(map[*crl.Info][]*x509.Certificate, len(ctx.CRLs))
	for _, crlInfo := range ctx.CRLs {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}
		ctx.crlIssuerPools[crlInfo] = issuerCertsForCRL(ctx, crlInfo.CRL)
	}
	return ctx
}

func combinedCRLIssuerPool(ctx Context) []*x509.Certificate {
	pool := make([]*x509.Certificate, 0, len(ctx.Chain))
	seen := make(map[*x509.Certificate]struct{})
	for _, crlInfo := range ctx.CRLs {
		candidates := ctx.crlIssuerPools[crlInfo]
		for _, candidate := range candidates {
			if candidate == nil {
				continue
			}
			if _, duplicate := seen[candidate]; duplicate {
				continue
			}
			seen[candidate] = struct{}{}
			pool = append(pool, candidate)
		}
	}
	return pool
}

// ExtractCertsFromInfo extracts x509 certificates from cert.Info values.
func ExtractCertsFromInfo(infos []*cert.Info) []*x509.Certificate {
	return cert.CertsFromInfos(infos)
}
