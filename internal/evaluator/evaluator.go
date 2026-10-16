// Package evaluator provides certificate evaluation against policies.
package evaluator

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/certnode"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/crlnode"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/ocspnode"
	"github.com/cavoq/PCL/internal/operator"
	pathpkg "github.com/cavoq/PCL/internal/path"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/source"
	"github.com/zmap/zcrypto/x509"
)

// Context contains all data needed for policy evaluation.
type Context struct {
	Policies []policy.Policy
	Registry *operator.Registry
	CRLs     []*crl.Info
	OCSPs    []*ocsp.Info
	Chain    []*cert.Info
	// Certificates are all other known certificates: supplied, climbed or
	// downloaded to find signers. Those outside Chain, such as separate
	// CRL-signing or indirect CRL issuer certificates, remain CRL signer
	// candidates and issuer candidates for delegated OCSP responders.
	// Evaluation never downloads certificates itself.
	Certificates []*cert.Info
	// RevocationRequested records that the caller requested CRL checking even
	// when acquisition produced no usable lists. In that case the certificate
	// receives an explicit Unknown assessment rather than silently skipping the
	// revocation policy.
	RevocationRequested bool
	ValidationTime      time.Time
	// CRLSignerAuthorizer decides whether a CRL signer that passed the CRL
	// checks may sign for the target certificate. Nil selects the default:
	// signers in the chain are authorized, other signers must be valid and
	// not revoked under the same CRLs.
	CRLSignerAuthorizer crl.SignerAuthorizer

	// ApplicationPurpose is an optional friendly EKU name or dotted EKU OID
	// projected into certificate trees and supplied to certificate operators.
	ApplicationPurpose string

	// PeerNames are reference identities the target certificate must present;
	// path validation checks them.
	PeerNames []cert.PeerName

	// CertificatePolicyInputs are the caller's RFC 5280 Section 6.1.1
	// certificate-policy processing inputs.
	CertificatePolicyInputs operator.CertificatePolicyInputs

	// Explicit certification-path validation inputs. Without trust anchors,
	// evaluation preserves the profile-linting behavior and does not infer
	// trust from a self-signed chain top.
	TrustAnchors      []*cert.Info
	MaximumPathLength *int
	// PathRevocation is the path revocation mode; unset means
	// pathpkg.DefaultRevocationMode.
	PathRevocation pathpkg.RevocationMode
}

// Subject is one evaluated input: the node tree policies see, the context
// operators receive, and the policies selected for it. Context.Input
// identifies the input.
type Subject struct {
	Tree     *node.Node
	Context  *operator.EvaluationContext
	Policies []policy.Policy
}

// Evaluate applies each subject's policies to its tree.
func Evaluate(subjects []Subject, registry *operator.Registry) []policy.Result {
	count := 0
	for _, subject := range subjects {
		count += len(subject.Policies)
	}
	results := make([]policy.Result, 0, count)
	for _, subject := range subjects {
		results = append(results, evaluatePolicies(subject.Policies, subject.Tree, registry, subject.Context)...)
	}
	return results
}

func Chain(ctx Context) []policy.Result {
	return Evaluate(ChainSubjects(ctx), ctx.Registry)
}

func OCSP(ctx Context) []policy.Result {
	return Evaluate(OCSPSubjects(ctx), ctx.Registry)
}

func CRL(ctx Context) []policy.Result {
	return Evaluate(CRLSubjects(ctx), ctx.Registry)
}

// ChainSubjects returns one subject per certificate in the chain, with the
// application purpose, download metadata and revocation assessment projected
// into its tree.
func ChainSubjects(ctx Context) []Subject {
	now := evaluationTime(ctx.ValidationTime)
	lists := revocationLists(ctx.CRLs)
	allCRLIssuers := crlSignerPool(ctx)
	ocspIssuers := cert.CertsFromInfos(ctx.Chain)
	authorizer := ctx.CRLSignerAuthorizer
	var pathAuthorizer *pathSignerAuthorizer
	if authorizer == nil {
		pathAuthorizer = newPathSignerAuthorizer(ctx, now)
		authorizer = pathAuthorizer
	}
	catalog := crl.NewCatalog(lists, crl.RevocationContext{
		Now:             now,
		Issuers:         allCRLIssuers,
		UseDeltas:       true,
		AuthorizeSigner: authorizer,
	})
	if pathAuthorizer != nil {
		pathAuthorizer.catalog = catalog
	}
	pathValidation := validateCertificationPath(ctx, now, catalog, ocspIssuers)

	var subjects []Subject
	for index, c := range ctx.Chain {
		if c == nil || c.Cert == nil {
			continue
		}
		tree := certnode.BuildTree(c.Cert)
		projectApplicationPurpose(tree, ctx.ApplicationPurpose)
		projectTrustAnchor(tree, c, ctx.TrustAnchors)
		if index == 0 && pathValidation != nil {
			projectPathValidation(tree, *pathValidation)
		}

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
			operator.WithCertificatePolicyInputs(ctx.CertificatePolicyInputs),
			operator.WithEvaluationTime(now),
			operator.WithCRLIssuers(allCRLIssuers),
		}
		if index == 0 && pathValidation != nil {
			evalOpts = append(evalOpts, operator.WithPathValidation(pathValidation))
		}
		subjects = append(subjects, Subject{
			Tree:     tree,
			Context:  operator.NewEvaluationContext(tree, c, ctx.Chain, evalOpts...),
			Policies: policy.ByCertificate(ctx.Policies, c.Cert),
		})
	}
	return subjects
}

// OCSPSubjects returns one subject per OCSP response, each followed by its
// embedded delegated signer certificate, if any.
func OCSPSubjects(ctx Context) []Subject {
	var subjects []Subject
	now := evaluationTime(ctx.ValidationTime)
	filteredPolicies := policy.ByInput(ctx.Policies, policy.InputOCSP)

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo == nil || ocspInfo.Response == nil {
			continue
		}

		tree := ocspnode.BuildTree(ocspInfo.Response)
		if tree == nil {
			continue
		}

		evalOpts := []operator.ContextOption{
			operator.WithInput(operator.Input{
				Kind:   operator.KindOCSP,
				Path:   ocspInfo.FilePath,
				Source: ocspInfo.Source,
			}),
			operator.WithOCSPs(ctx.OCSPs),
			operator.WithEvaluationTime(now),
		}
		subjects = append(subjects, Subject{
			Tree:     tree,
			Context:  operator.NewEvaluationContext(tree, nil, ctx.Chain, evalOpts...),
			Policies: filteredPolicies,
		})

		if ocspInfo.Response.Certificate != nil {
			if signer, ok := ocspSignerSubject(ctx, ocspInfo, now); ok {
				subjects = append(subjects, signer)
			}
		}
	}

	return subjects
}

// CRLSubjects returns one subject per CRL.
func CRLSubjects(ctx Context) []Subject {
	var subjects []Subject
	now := evaluationTime(ctx.ValidationTime)
	issuerCerts := crlSignerPool(ctx)

	for _, crlInfo := range ctx.CRLs {
		if crlInfo == nil || crlInfo.CRL == nil {
			continue
		}

		tree := crlnode.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
		if tree == nil {
			continue
		}

		evalOpts := []operator.ContextOption{
			operator.WithInput(operator.Input{
				Kind:   operator.KindCRL,
				Path:   crlInfo.FilePath,
				Source: crlInfo.Source,
			}),
			operator.WithCRLs(ctx.CRLs),
			operator.WithCurrentCRL(crlInfo),
			operator.WithCRLIssuers(issuerCerts),
			operator.WithEvaluationTime(now),
		}
		subjects = append(subjects, Subject{
			Tree:     tree,
			Context:  operator.NewEvaluationContext(tree, nil, ctx.Chain, evalOpts...),
			Policies: policy.ByCRL(ctx.Policies, crlInfo.CRL),
		})
	}

	return subjects
}

func ocspSignerSubject(ctx Context, ocspInfo *ocsp.Info, now time.Time) (Subject, bool) {
	zcryptoSignerCert, err := ocspInfo.ResponderCertificate()
	if err != nil || zcryptoSignerCert == nil {
		return Subject{}, false
	}

	ocspSignerTree := certnode.BuildTree(zcryptoSignerCert)
	ocspSignerInfo := &cert.Info{
		Cert:     zcryptoSignerCert,
		FilePath: ocspInfo.FilePath + " (signing cert)",
		Source:   source.Info{Type: source.Extracted, Description: "extracted from OCSP response"},
	}

	signerChain := ocsp.SignerChain(ocspSignerInfo, ctx.Chain, ctx.Certificates)
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
		operator.WithCertificatePolicyInputs(ctx.CertificatePolicyInputs),
		operator.WithEvaluationTime(now),
	}
	return Subject{
		Tree:     ocspSignerTree,
		Context:  operator.NewEvaluationContext(ocspSignerTree, ocspSignerInfo, signerChain, evalOpts...),
		Policies: policy.ByCertificate(ctx.Policies, zcryptoSignerCert),
	}, true
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

// pathSignerAuthorizer is the default CRL signer decision. A signer in the
// evaluated chain is authorized. Any other signer, such as a separate
// CRL-signing certificate or an indirect CRL issuer, must be within its
// validity period and have Good status under the same CRLs (RFC 5280 6.3.3
// (f)). A signer may be covered by a CRL it signed itself.
type pathSignerAuthorizer struct {
	chain        *cert.CertificateSet
	candidates   []*cert.Info
	trustAnchors []*cert.Info
	maxDepth     int
	now          time.Time
	catalog      *crl.Catalog
	visiting     *cert.CertificateSet
	visitingMu   sync.Mutex

	// anchoredSigners caches whether a signer has a valid path to the trust
	// anchors. Every input to that decision is fixed for the authorizer, and
	// the same signer is checked once per CRL and certificate it covers.
	anchoredSigners   map[[32]byte]bool
	anchoredSignersMu sync.Mutex
}

func newPathSignerAuthorizer(ctx Context, now time.Time) *pathSignerAuthorizer {
	return &pathSignerAuthorizer{
		chain:        cert.NewCertificateSet(cert.CertsFromInfos(ctx.Chain)...),
		candidates:   crlSignerCandidates(ctx),
		trustAnchors: append([]*cert.Info(nil), ctx.TrustAnchors...),
		maxDepth:     len(ctx.Certificates) + len(ctx.Chain) + len(ctx.TrustAnchors) + 1,
		now:          now,
		visiting:     cert.NewCertificateSet(),

		anchoredSigners: make(map[[32]byte]bool),
	}
}

func (authorizer *pathSignerAuthorizer) AuthorizeCRLSigner(
	_, signer *x509.Certificate,
	_ *x509.RevocationList,
) bool {
	if len(authorizer.trustAnchors) > 0 {
		if !authorizer.signerAnchored(signer) {
			return false
		}
		if authorizer.chain.Contains(signer) {
			return true
		}
	} else if authorizer.chain.Contains(signer) {
		return true
	}
	if authorizer.now.Before(signer.NotBefore) || authorizer.now.After(signer.NotAfter) {
		return false
	}
	if authorizer.catalog == nil {
		return false
	}
	authorizer.visitingMu.Lock()
	added := authorizer.visiting.Add(signer)
	authorizer.visitingMu.Unlock()
	if !added {
		// The signer's own status is being assessed and depends on a CRL it
		// signed, as for an indirect CRL issuer covered by its own CRL (PKITS
		// 4.14.30). Accept provisionally; that CRL decides whether the
		// signer is revoked.
		return true
	}
	defer func() {
		authorizer.visitingMu.Lock()
		authorizer.visiting.Remove(signer)
		authorizer.visitingMu.Unlock()
	}()
	assessment := authorizer.catalog.AssessCertificate(signer)
	return assessment.Status() == crl.RevocationGood
}

// signerAnchored reports whether signer has a valid path to the trust
// anchors at the validation time, deciding each signer once.
func (authorizer *pathSignerAuthorizer) signerAnchored(signer *x509.Certificate) bool {
	key := sha256.Sum256(signer.Raw)
	authorizer.anchoredSignersMu.Lock()
	anchored, decided := authorizer.anchoredSigners[key]
	authorizer.anchoredSignersMu.Unlock()
	if decided {
		return anchored
	}

	construction, err := pathpkg.Construct(
		[]*cert.Info{{Cert: signer}},
		authorizer.candidates,
		authorizer.trustAnchors,
		authorizer.maxDepth,
	)
	anchored = err == nil && construction.Anchored && pathpkg.Validate(pathpkg.Inputs{
		Chain:          construction.Chain,
		TrustAnchors:   authorizer.trustAnchors,
		ValidationTime: authorizer.now,
		Policy:         pathpkg.PolicyInputs{Configured: true},
		RevocationMode: pathpkg.RevocationNone,
	}).Valid

	authorizer.anchoredSignersMu.Lock()
	authorizer.anchoredSigners[key] = anchored
	authorizer.anchoredSignersMu.Unlock()
	return anchored
}

func validateCertificationPath(
	ctx Context,
	now time.Time,
	catalog *crl.Catalog,
	ocspIssuers []*x509.Certificate,
) *pathpkg.Result {
	if len(ctx.TrustAnchors) == 0 || len(ctx.Chain) == 0 {
		return nil
	}
	checker := pathpkg.RevocationCheckerFunc(func(certificate *x509.Certificate) pathpkg.RevocationDecision {
		crlAssessment := catalog.AssessCertificate(certificate)
		ocspAssessment := ocsp.AssessCertificate(certificate, ctx.OCSPs, ocspIssuers, now)
		crlStatus := crlAssessment.Status()
		ocspStatus := ocspAssessment.Status()
		decision := pathpkg.RevocationDecision{
			Available: len(crlAssessment.Evidence) > 0 || ocspStatus != ocsp.StatusNotApplicable,
			Status:    pathpkg.RevocationUnknown,
			Details: fmt.Sprintf(
				"CRL=%s, OCSP=%s",
				revocationStatusName(crlStatus),
				ocspStatusName(ocspStatus),
			),
		}
		switch {
		case crlStatus == crl.RevocationRevoked || ocspStatus == ocsp.StatusRevoked:
			decision.Status = pathpkg.RevocationRevoked
		case crlStatus == crl.RevocationGood || ocspStatus == ocsp.StatusGood:
			decision.Status = pathpkg.RevocationGood
		}
		return decision
	})
	result := pathpkg.Validate(pathpkg.Inputs{
		Chain:              ctx.Chain,
		TrustAnchors:       ctx.TrustAnchors,
		ValidationTime:     now,
		Policy:             ctx.CertificatePolicyInputs,
		MaximumPathLength:  ctx.MaximumPathLength,
		ApplicationPurpose: ctx.ApplicationPurpose,
		PeerNames:          ctx.PeerNames,
		RevocationMode:     ctx.PathRevocation,
		CheckRevocation:    checker,
	})
	return &result
}

func projectPathValidation(tree *node.Node, result pathpkg.Result) {
	if tree == nil {
		return
	}
	validation := node.New("pathValidation", nil)
	validation.Children["valid"] = node.New("valid", result.Valid)
	validation.Children["anchored"] = node.New("anchored", result.Anchored)
	validation.Children["findingCount"] = node.New("findingCount", len(result.Findings))
	if summary := result.FailureSummary(); summary != "" {
		validation.Children["failureSummary"] = node.New("failureSummary", summary)
	}
	findings := node.New("findings", nil)
	for _, finding := range result.Findings {
		findingNode := node.New("finding", finding.Message)
		findingNode.Children["code"] = node.New("code", finding.Code)
		findingNode.Children["reference"] = node.New("reference", finding.Reference)
		findingNode.Children["status"] = node.New("status", string(finding.Status))
		findingNode.Children["certificateIndex"] = node.New("certificateIndex", finding.CertificateIndex)
		if finding.CertificateSubject != "" {
			findingNode.Children["certificateSubject"] = node.New("certificateSubject", finding.CertificateSubject)
		}
		findings.AddElement(findingNode)
	}
	validation.Children["findings"] = findings
	tree.Children["pathValidation"] = validation
}

func ocspStatusName(status ocsp.Status) string {
	switch status {
	case ocsp.StatusGood:
		return "good"
	case ocsp.StatusRevoked:
		return "revoked"
	case ocsp.StatusUnknown:
		return "unknown"
	default:
		return "not-applicable"
	}
}

// projectTrustAnchor records whether a chain certificate is one of the
// explicit trust anchors. Trust anchors are trusted as given (RFC 5280 6.1.1),
// so rules about a certificate's relation to its issuer can exclude them. The
// node is absent without explicit trust anchors.
func projectTrustAnchor(tree *node.Node, info *cert.Info, anchors []*cert.Info) {
	if tree == nil || len(anchors) == 0 {
		return
	}
	anchor := slices.ContainsFunc(anchors, func(anchor *cert.Info) bool {
		return anchor != nil && cert.SameCertificate(anchor.Cert, info.Cert)
	})
	tree.Children["trustAnchor"] = node.New("trustAnchor", anchor)
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

// evaluationTime is the configured time or the current time, truncated to
// whole seconds: certificate, CRL and OCSP times have one-second
// granularity (RFC 5280 4.1.2.5), so an instant within the notAfter second
// still lies within the validity period.
func evaluationTime(configured time.Time) time.Time {
	if configured.IsZero() {
		configured = time.Now()
	}
	return configured.Truncate(time.Second)
}

// crlSignerCandidates returns the chain followed by the other supplied
// certificates, each certificate once.
func crlSignerCandidates(ctx Context) []*cert.Info {
	candidates := append([]*cert.Info(nil), ctx.Chain...)
	seen := cert.NewCertificateSet(cert.CertsFromInfos(ctx.Chain)...)
	for _, info := range ctx.Certificates {
		if info != nil && info.Cert != nil && seen.Add(info.Cert) {
			candidates = append(candidates, info)
		}
	}
	return candidates
}

// crlSignerPool returns the CRL signer candidates: the chain followed by the
// other known certificates.
func crlSignerPool(ctx Context) []*x509.Certificate {
	return cert.CertsFromInfos(crlSignerCandidates(ctx))
}
