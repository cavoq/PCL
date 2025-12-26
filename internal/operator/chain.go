package operator

import (
	"bytes"

	"github.com/cavoq/PCL/internal/node"
)

type SignedBy struct{}

func (SignedBy) Name() string { return "signedBy" }

func (SignedBy) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	position := ctx.Cert.Position

	if ctx.Cert.Type == "root" {
		err := cert.CheckSignatureFrom(cert)
		return err == nil, nil
	}

	if position+1 >= len(ctx.Chain) {
		return false, nil
	}

	issuer := ctx.Chain[position+1]
	if issuer == nil || issuer.Cert == nil {
		return false, nil
	}

	err := cert.CheckSignatureFrom(issuer.Cert)
	return err == nil, nil
}

type IssuedBy struct{}

func (IssuedBy) Name() string { return "issuedBy" }

func (IssuedBy) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	position := ctx.Cert.Position

	if ctx.Cert.Type == "root" {
		return cert.Issuer.String() == cert.Subject.String(), nil
	}

	if position+1 >= len(ctx.Chain) {
		return false, nil
	}

	issuer := ctx.Chain[position+1]
	if issuer == nil || issuer.Cert == nil {
		return false, nil
	}

	return cert.Issuer.String() == issuer.Cert.Subject.String(), nil
}

type AKIMatchesSKI struct{}

func (AKIMatchesSKI) Name() string { return "akiMatchesSki" }

func (AKIMatchesSKI) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	position := ctx.Cert.Position

	// If no AKI, this check doesn't apply
	if len(cert.AuthorityKeyId) == 0 {
		return true, nil
	}

	// Root certificates: AKI should match own SKI (if present)
	if ctx.Cert.Type == "root" {
		if len(cert.SubjectKeyId) == 0 {
			return true, nil
		}
		return bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId), nil
	}

	// For other certificates, check against issuer's SKI
	if position+1 >= len(ctx.Chain) {
		return false, nil
	}

	issuer := ctx.Chain[position+1]
	if issuer == nil || issuer.Cert == nil {
		return false, nil
	}

	// If issuer has no SKI, we can't verify
	if len(issuer.Cert.SubjectKeyId) == 0 {
		return true, nil
	}

	return bytes.Equal(cert.AuthorityKeyId, issuer.Cert.SubjectKeyId), nil
}
