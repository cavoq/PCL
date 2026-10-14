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
	// RevocationRequested records that the caller requested CRL checking even
	// when acquisition produced no usable lists. In that case the certificate
	// receives an explicit Unknown assessment rather than silently skipping the
	// revocation policy.
	RevocationRequested bool
	ValidationTime      time.Time
	// CRLSignerAuthorizer lets a path engine require the CRL signer to chain
	// to the target certificate's trust anchor. P3 leaves it nil; P4 can
	// supply the path-owned decision without changing or duplicating CRL
	// processing in the evaluator.
	CRLSignerAuthorizer crl.SignerAuthorizer

	// ApplicationPurpose is an optional friendly EKU name or dotted EKU OID
	// projected into certificate trees and supplied to certificate operators.
	ApplicationPurpose string

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
	now := evaluationTime(ctx.ValidationTime)
	lists := revocationLists(ctx.CRLs)
	allCRLIssuers := combinedCRLIssuerPool(ctx)
	ocspIssuers := cert.CertsFromInfos(ctx.Chain)
	catalog := crl.NewCatalog(lists, crl.RevocationContext{
		Now:             now,
		Issuers:         allCRLIssuers,
		UseDeltas:       true,
		AuthorizeSigner: ctx.CRLSignerAuthorizer,
	})

	for _, c := range ctx.Chain {
		if c == nil || c.Cert == nil {
			continue
		}
		tree := certzcrypto.BuildTree(c.Cert)
		projectApplicationPurpose(tree, ctx.ApplicationPurpose)

		if c.Source.Format != "" && c.Source.Type != source.Local {
			tree.Children["downloadFormat"] = node.New("downloadFormat", c.Source.Format)
			tree.Children["downloadURL"] = node.New("downloadURL", c.Source.URL)
		}

		crlAssessment := catalog.AssessCertificate(c.Cert)
		ocspAssessment := ocsp.AssessCertificate(c.Cert, ctx.OCSPs, ocspIssuers, now)
		if ctx.RevocationRequested || len(lists) > 0 {
			projectRevocationAssessment(tree, crlAssessment)
		}

		evalOpts := []operator.ContextOption{
			operator.WithCRLs(ctx.CRLs),
			operator.WithCRLAssessment(&crlAssessment),
			operator.WithOCSPs(ctx.OCSPs),
			operator.WithOCSPAssessment(&ocspAssessment),
			operator.WithApplicationPurpose(ctx.ApplicationPurpose),
			operator.WithEvaluationTime(now),
			operator.WithCRLIssuers(allCRLIssuers),
		}
		evalCtx := operator.NewEvaluationContext(tree, c, ctx.Chain, evalOpts...)

		results = append(results, evaluatePolicies(policy.ByCertificate(ctx.Policies, c.Cert), tree, ctx.Registry, evalCtx)...)
	}

	return results
}

func OCSP(ctx Context) []policy.Result {
	var results []policy.Result
	now := evaluationTime(ctx.ValidationTime)
	filteredPolicies := policy.ByInput(ctx.Policies, policy.InputOCSP)

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo == nil || ocspInfo.Response == nil {
			continue
		}

		tree := ocspzcrypto.BuildTree(ocspInfo.Response)
		if tree == nil {
			continue
		}

		ocspCertInfo := &cert.Info{
			FilePath: ocspInfo.FilePath,
			Type:     "ocsp",
			Source:   ocspInfo.Source,
		}

		evalOpts := []operator.ContextOption{
			operator.WithOCSPs(ctx.OCSPs),
			operator.WithEvaluationTime(now),
		}
		evalCtx := operator.NewEvaluationContext(tree, ocspCertInfo, ctx.Chain, evalOpts...)

		results = append(results, evaluatePolicies(filteredPolicies, tree, ctx.Registry, evalCtx)...)

		if ocspInfo.Response.Certificate != nil {
			results = append(results, ocspSigningCert(ctx, ocspInfo, now)...)
		}
	}

	return results
}

func CRL(ctx Context) []policy.Result {
	ctx = PrepareCRLIssuers(ctx)
	var results []policy.Result
	now := evaluationTime(ctx.ValidationTime)

	for _, crlInfo := range ctx.CRLs {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}

		issuerCerts := ctx.crlIssuerPools[crlInfo]

		tree := crl.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
		if tree == nil {
			continue
		}

		crlCertInfo := &cert.Info{
			FilePath: crlInfo.FilePath,
			Type:     "crl",
			Source:   crlInfo.Source,
		}

		evalOpts := []operator.ContextOption{
			operator.WithCRLs(ctx.CRLs),
			operator.WithCurrentCRL(crlInfo),
			operator.WithCRLIssuers(issuerCerts),
			operator.WithEvaluationTime(now),
		}
		evalCtx := operator.NewEvaluationContext(tree, crlCertInfo, ctx.Chain, evalOpts...)

		results = append(results, evaluatePolicies(policy.ByCRL(ctx.Policies, crlInfo.CRL), tree, ctx.Registry, evalCtx)...)
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

func ocspSigningCert(ctx Context, ocspInfo *ocsp.Info, now time.Time) []policy.Result {
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
	ocspAssessment := ocsp.AssessCertificate(
		zcryptoSignerCert,
		ctx.OCSPs,
		cert.CertsFromInfos(signerChain),
		now,
	)

	// A delegated OCSP signer is evaluated for its OCSP-signing role, not for
	// the application purpose requested for the supplied certificate chain.
	evalOpts := []operator.ContextOption{
		operator.WithOCSPs(ctx.OCSPs),
		operator.WithOCSPAssessment(&ocspAssessment),
		operator.WithEvaluationTime(now),
	}
	evalCtx := operator.NewEvaluationContext(ocspSignerTree, ocspSignerInfo, signerChain, evalOpts...)

	signerPolicies := policy.ByCertificate(ctx.Policies, zcryptoSignerCert)
	return evaluatePolicies(signerPolicies, ocspSignerTree, ctx.Registry, evalCtx)
}

func evaluatePolicies(
	policies []policy.Policy,
	tree *node.Node,
	registry *operator.Registry,
	evalCtx *operator.EvaluationContext,
) []policy.Result {
	results := make([]policy.Result, 0, len(policies))
	for _, p := range policies {
		results = append(results, policy.Evaluate(p, tree, registry, evalCtx))
	}
	return results
}

func projectApplicationPurpose(tree *node.Node, purpose string) {
	if tree == nil || purpose == "" {
		return
	}
	tree.Children["applicationPurpose"] = node.New("applicationPurpose", purpose)
}

func projectRevocationAssessment(tree *node.Node, assessment crl.Assessment) {
	if tree == nil {
		return
	}

	revocation := node.New("revocation", nil)
	revocation.Children["status"] = node.New("status", revocationStatusName(assessment.Status()))
	revocation.Children["evidenceCount"] = node.New("evidenceCount", len(assessment.Evidence))
	revocation.Children["coveredReasons"] = node.New(
		"coveredReasons",
		int(assessment.CoveredReasons),
	)
	if assessment.Revocation != nil {
		revocation.Children["reasonCode"] = node.New("reasonCode", assessment.Revocation.ReasonCode)
		revocation.Children["revocationTime"] = node.New(
			"revocationTime",
			assessment.Revocation.RevocationTime,
		)
	}
	tree.Children["revocation"] = revocation
}

func revocationStatusName(status crl.RevocationStatus) string {
	switch status {
	case crl.RevocationGood:
		return "good"
	case crl.RevocationRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

func revocationLists(infos []*crl.Info) []*x509.RevocationList {
	lists := make([]*x509.RevocationList, 0, len(infos))
	for _, info := range infos {
		if info != nil && info.CRL != nil {
			lists = append(lists, info.CRL)
		}
	}
	return lists
}

func evaluationTime(configured time.Time) time.Time {
	if !configured.IsZero() {
		return configured
	}
	return time.Now()
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
