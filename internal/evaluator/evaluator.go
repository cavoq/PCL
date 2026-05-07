package evaluator

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
	"github.com/cavoq/PCL/internal/policy/match"
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
}

func Chain(ctx Context) []policy.Result {
	var results []policy.Result

	for _, c := range ctx.Chain {
		tree := certzcrypto.BuildTree(c.Cert)

		if c.Source.Format != "" && c.Source.Type != source.Local {
			tree.Children["downloadFormat"] = node.New("downloadFormat", c.Source.Format)
			tree.Children["downloadURL"] = node.New("downloadURL", c.Source.URL)
		}

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

		filteredPolicies := match.ByCertificate(ctx.Policies, c.Cert)
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

		filteredPolicies := match.ByInput(ctx.Policies, match.InputOCSP)
		for _, p := range filteredPolicies {
			res := policy.Evaluate(p, tree, ctx.Registry, evalCtx)
			results = append(results, res)
		}

		if ocspInfo.Response.Certificate != nil {
			results = append(results, ocspSigningCert(ctx.Policies, ctx.Registry, ctx.OCSPs, ocspInfo, ctx.Chain)...)
		}
	}

	return results
}

func CRL(ctx Context) []policy.Result {
	var results []policy.Result

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}

		issuerCerts := ExtractCertsFromInfo(ctx.Chain)

		crlNode := crlzcrypto.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
		if crlNode == nil {
			continue
		}

		crlCertInfo := &cert.Info{
			FilePath: crlInfo.FilePath,
			Type:     "crl",
			Source:   crlInfo.Source,
		}

		tree := crlNode
		evalOpts := []operator.ContextOption{operator.WithCRLs(ctx.CRLs)}
		evalCtx := operator.NewEvaluationContext(tree, crlCertInfo, ctx.Chain, evalOpts...)

		filteredPolicies := match.ByCRL(ctx.Policies, crlInfo.CRL)
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

func ocspSigningCert(policies []policy.Policy, registry *operator.Registry, ocsps []*ocsp.Info, ocspInfo *ocsp.Info, chain []*cert.Info) []policy.Result {
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
	signerPolicies := match.ByCertificate(policies, zcryptoSignerCert)
	for _, p := range signerPolicies {
		res := policy.Evaluate(p, ocspSignerTree, registry, evalCtx)
		results = append(results, res)
	}

	return results
}

// ExtractCertsFromInfo extracts x509 certificates from cert.Info values.
func ExtractCertsFromInfo(infos []*cert.Info) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, info := range infos {
		if info.Cert != nil {
			certs = append(certs, info.Cert)
		}
	}
	return certs
}
