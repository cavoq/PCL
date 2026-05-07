package linter

import (
	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/source"
	"github.com/cavoq/PCL/internal/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

// EvaluationContext contains all data needed for policy evaluation.
type EvaluationContext struct {
	Policies []policy.Policy
	Registry *operator.Registry
	CRLs     []*crl.Info
	OCSPs    []*ocsp.Info
	Chain    []*cert.Info
}

// evaluateChain evaluates policies for each certificate in the chain.
func evaluateChain(ctx EvaluationContext) []policy.Result {
	var results []policy.Result

	for _, c := range ctx.Chain {
		tree := certzcrypto.BuildTree(c.Cert)

		// Add download format to tree for PEM format detection rule
		if c.Source.Format != "" && c.Source.Type != source.Local {
			tree.Children["downloadFormat"] = node.New("downloadFormat", c.Source.Format)
			tree.Children["downloadURL"] = node.New("downloadURL", c.Source.URL)
		}

		// Add CRL node to tree if CRLs are present
		if len(ctx.CRLs) > 0 {
			for _, crlInfo := range ctx.CRLs {
				if crlInfo.CRL != nil {
					crlNode := crlzcrypto.BuildTree(crlInfo.CRL)
					if crlNode != nil {
						tree.Children["crl"] = crlNode
					}
					break
				}
			}
		}

		evalOpts := []operator.ContextOption{
			operator.WithCRLs(ctx.CRLs),
			operator.WithOCSPs(ctx.OCSPs),
		}
		evalCtx := operator.NewEvaluationContext(tree, c, ctx.Chain, evalOpts...)

		// Filter policies by certificate type
		filteredPolicies := filterPoliciesByCert(ctx.Policies, c.Cert)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}
	}

	return results
}

// evaluateOCSP evaluates policies for OCSP responses and signing certificates.
func evaluateOCSP(ctx EvaluationContext) []policy.Result {
	var results []policy.Result

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}

		ocspNode := ocspzcrypto.BuildTree(ocspInfo.Response)
		if ocspNode == nil {
			continue
		}

		// Create synthetic cert.Info for OCSP response to set proper CertType
		ocspCertInfo := &cert.Info{
			FilePath: ocspInfo.FilePath,
			Type:     "ocsp",
			Source:   ocspInfo.Source,
		}

		tree := ocspNode
		evalOpts := []operator.ContextOption{operator.WithOCSPs(ctx.OCSPs)}
		evalCtx := operator.NewEvaluationContext(tree, ocspCertInfo, ctx.Chain, evalOpts...)

		filteredPolicies := filterPoliciesByInput(ctx.Policies, AppliesToOCSP)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}

		// Evaluate OCSP signing certificate if present in response
		if ocspInfo.Response.Certificate != nil {
			results = append(results, evaluateOCSPSigningCert(ctx.Policies, ctx.Registry, ctx.OCSPs, ocspInfo, ctx.Chain)...)
		}
	}

	return results
}

// evaluateOCSPSigningCert evaluates policies for OCSP signing certificate.
func evaluateOCSPSigningCert(policies []policy.Policy, registry *operator.Registry, ocsps []*ocsp.Info, ocspInfo *ocsp.Info, chain []*cert.Info) []policy.Result {
	// Convert standard cert to zcrypto cert
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

	evalOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
	evalCtx := operator.NewEvaluationContext(ocspSignerTree, ocspSignerInfo, chain, evalOpts...)

	var results []policy.Result
	signerPolicies := filterPoliciesByCert(policies, zcryptoSignerCert)
	for _, p := range signerPolicies {
		res := policy.Evaluate(p, ocspSignerTree, registry, evalCtx)
		results = append(results, res)
	}

	return results
}

// evaluateCRL evaluates policies for CRLs with a certificate chain.
func evaluateCRL(ctx EvaluationContext) []policy.Result {
	var results []policy.Result

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}

		// Build issuer certificates list from chain
		issuerCerts := extractCertsFromInfo(ctx.Chain)

		crlNode := crlzcrypto.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
		if crlNode == nil {
			continue
		}

		// Create synthetic cert.Info for CRL to set proper CertType
		crlCertInfo := &cert.Info{
			FilePath: crlInfo.FilePath,
			Type:     "crl",
			Source:   crlInfo.Source,
		}

		tree := crlNode
		evalOpts := []operator.ContextOption{operator.WithCRLs(ctx.CRLs)}
		evalCtx := operator.NewEvaluationContext(tree, crlCertInfo, ctx.Chain, evalOpts...)

		// Filter policies by CRL type
		hasDelta := hasDeltaCRLIndicator(crlInfo.CRL)
		isIndirect := isIndirectCRL(crlInfo.CRL)
		filteredPolicies := filterPoliciesByCRL(ctx.Policies, hasDelta, isIndirect)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}
	}

	return results
}

// evaluateCRLOnly evaluates CRLs independently without a certificate chain.
func evaluateCRLOnly(policies []policy.Policy, registry *operator.Registry, crls []*crl.Info, issuers []*cert.Info) []policy.Result {
	var results []policy.Result

	for _, crlInfo := range crls {
		if crlInfo.CRL == nil {
			continue
		}

		// Build issuer certificates list for CRL type detection
		issuerCerts := extractCertsFromInfo(issuers)

		crlNode := crlzcrypto.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
		if crlNode == nil {
			continue
		}

		// Create synthetic cert.Info for CRL to set proper CertType
		crlCertInfo := &cert.Info{
			FilePath: crlInfo.FilePath,
			Type:     "crl",
			Source:   crlInfo.Source,
		}

		tree := crlNode
		evalOpts := []operator.ContextOption{operator.WithCRLs(crls)}
		evalCtx := operator.NewEvaluationContext(tree, crlCertInfo, issuers, evalOpts...)

		// Filter policies by CRL type
		hasDelta := hasDeltaCRLIndicator(crlInfo.CRL)
		isIndirect := isIndirectCRL(crlInfo.CRL)
		filteredPolicies := filterPoliciesByCRL(policies, hasDelta, isIndirect)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, registry, evalCtx)
			results = append(results, res)
		}
	}

	return results
}

// evaluateOCSPOnly evaluates OCSP responses independently without a certificate chain.
func evaluateOCSPOnly(policies []policy.Policy, registry *operator.Registry, ocsps []*ocsp.Info) []policy.Result {
	var results []policy.Result

	for _, ocspInfo := range ocsps {
		if ocspInfo.Response == nil {
			continue
		}

		ocspNode := ocspzcrypto.BuildTree(ocspInfo.Response)
		if ocspNode == nil {
			continue
		}

		// Create synthetic cert.Info for OCSP response to set proper CertType
		ocspCertInfo := &cert.Info{
			FilePath: ocspInfo.FilePath,
			Type:     "ocsp",
			Source:   ocspInfo.Source,
		}

		tree := ocspNode
		evalOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
		evalCtx := operator.NewEvaluationContext(tree, ocspCertInfo, nil, evalOpts...)

		// Filter policies by input type (OCSP)
		filteredPolicies := filterPoliciesByInput(policies, AppliesToOCSP)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, registry, evalCtx)
			results = append(results, res)
		}

		// Evaluate OCSP signing certificate if present in response
		if ocspInfo.Response.Certificate != nil {
			results = append(results, evaluateOCSPSigningCert(policies, registry, ocsps, ocspInfo, nil)...)
		}
	}

	return results
}

// extractCertsFromInfo extracts x509 certificates from cert.Info slice.
func extractCertsFromInfo(infos []*cert.Info) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, info := range infos {
		if info.Cert != nil {
			certs = append(certs, info.Cert)
		}
	}
	return certs
}
