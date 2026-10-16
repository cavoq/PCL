package operator

import (
	"bytes"

	certpkg "github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/zmap/zcrypto/x509"
)

type SignatureValid struct{}

func (SignatureValid) Name() string { return "signatureValid" }

func (SignatureValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	if ctx.Input.Kind == certpkg.TypeRoot {
		err := certpkg.CheckSignatureFrom(cert, cert)
		return err == nil, nil
	}

	issuer, err := suppliedIssuer(ctx)
	if err != nil {
		return false, err
	}

	err = certpkg.CheckSignatureFrom(cert, issuer)
	return err == nil, nil
}

type IssuedBy struct{}

func (IssuedBy) Name() string { return "issuedBy" }

func (IssuedBy) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	if ctx.Input.Kind == certpkg.TypeRoot {
		return certpkg.IsSelfIssued(cert), nil
	}

	issuer, err := suppliedIssuer(ctx)
	if err != nil {
		return false, err
	}

	return x509asn1.NamesMatchOrText(cert.RawIssuer, issuer.RawSubject, cert.Issuer.String(), issuer.Subject.String()), nil
}

type AKIMatchesSKI struct{}

func (AKIMatchesSKI) Name() string { return "akiMatchesSki" }

func (AKIMatchesSKI) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	// If no AKI, this check doesn't apply
	if len(cert.AuthorityKeyId) == 0 {
		return true, nil
	}

	// Root certificates: AKI should match own SKI (if present)
	if ctx.Input.Kind == certpkg.TypeRoot {
		if len(cert.SubjectKeyId) == 0 {
			return true, nil
		}
		return bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId), nil
	}

	// For other certificates, check against issuer's SKI
	issuer, err := suppliedIssuer(ctx)
	if err != nil {
		return false, err
	}

	// If issuer has no SKI, we can't verify
	if len(issuer.SubjectKeyId) == 0 {
		return true, nil
	}

	return bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId), nil
}

// suppliedIssuer returns the certificate's issuer from the evaluated chain.
// Without it a check against the issuer is undecided, not failed: the input
// is incomplete rather than shown non-compliant.
func suppliedIssuer(ctx *EvaluationContext) (*x509.Certificate, error) {
	issuer, ok := ctx.ChainIssuer()
	if !ok {
		return nil, NoEvidenceError{Evidence: "issuer certificate"}
	}
	return issuer, nil
}
