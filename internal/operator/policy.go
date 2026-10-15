package operator

import (
	"slices"

	"github.com/zmap/zcrypto/x509"

	certpkg "github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	pathpkg "github.com/cavoq/PCL/internal/path"
)

// CertificatePolicyInputs is retained as an API-compatible alias. The RFC
// 5280 policy state belongs to the path domain.
type CertificatePolicyInputs = pathpkg.PolicyInputs

// CertificatePolicyValid is the policy adapter for the RFC 5280 Section 6.1
// state machine owned by package path.
type CertificatePolicyValid struct{}

func (CertificatePolicyValid) Name() string { return "certificatePolicyValid" }

func (CertificatePolicyValid) Evaluate(_ *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if !ctx.HasCert() || !ctx.HasChain() {
		return false, nil
	}

	certificates, ok := certificatePolicyPath(ctx)
	if !ok {
		return false, nil
	}
	valid, err := pathpkg.ValidatePolicies(
		certificates,
		certificatePolicyInputs(ctx.CertificatePolicyInputs, operands),
	)
	if err != nil {
		// Policy rules historically fail closed on malformed policy extensions.
		return false, nil
	}
	return valid, nil
}

func certificatePolicyInputs(configured CertificatePolicyInputs, operands []any) CertificatePolicyInputs {
	if configured.IsConfigured() {
		return configured.Normalized()
	}

	var acceptable []string
	for _, operand := range operands {
		if policy, ok := operand.(string); ok {
			acceptable = append(acceptable, policy)
		}
	}
	if len(acceptable) == 0 {
		acceptable = []string{oid.AnyPolicy}
	}
	return CertificatePolicyInputs{
		InitialPolicySet:      acceptable,
		InitialExplicitPolicy: len(operands) > 0,
	}
}

// certificatePolicyPath returns certificates from the one issued by the
// trust anchor (certificate 1) down to the evaluated certificate
// (certificate n). The legacy adapter infers a self-signed chain top; the
// path validator receives explicit trust anchors instead.
func certificatePolicyPath(ctx *EvaluationContext) ([]*x509.Certificate, bool) {
	target := slices.IndexFunc(ctx.Chain, func(info *certpkg.Info) bool {
		return info != nil && info.Cert == ctx.Cert.Cert
	})
	if target < 0 {
		return nil, false
	}

	top := len(ctx.Chain) - 1
	if top > target && ctx.Chain[top] != nil && ctx.Chain[top].Cert != nil &&
		certpkg.IsSelfSigned(ctx.Chain[top].Cert) {
		top--
	}

	certificates := make([]*x509.Certificate, 0, top-target+1)
	for index := top; index >= target; index-- {
		if ctx.Chain[index] == nil || ctx.Chain[index].Cert == nil {
			return nil, false
		}
		certificates = append(certificates, ctx.Chain[index].Cert)
	}
	return certificates, true
}
