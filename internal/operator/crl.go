package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

type CRLValid struct{}

func (CRLValid) Name() string { return "crlValid" }

func (CRLValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || len(ctx.CRLs) == 0 {
		return false, nil
	}

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		if ctx.Now.Before(crl.ThisUpdate) {
			return false, nil
		}
		if !crl.NextUpdate.IsZero() && ctx.Now.After(crl.NextUpdate) {
			return false, nil
		}
	}

	return true, nil
}

type CRLNotExpired struct{}

func (CRLNotExpired) Name() string { return "crlNotExpired" }

func (CRLNotExpired) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || len(ctx.CRLs) == 0 {
		return false, nil
	}

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		if !crl.NextUpdate.IsZero() && ctx.Now.After(crl.NextUpdate) {
			return false, nil
		}
	}

	return true, nil
}

type CRLSignedBy struct{}

func (CRLSignedBy) Name() string { return "crlSignedBy" }

func (CRLSignedBy) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || len(ctx.CRLs) == 0 || len(ctx.Chain) == 0 {
		return false, nil
	}

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		verified := false
		for _, certInfo := range ctx.Chain {
			if certInfo.Cert == nil {
				continue
			}

			if crl.Issuer.String() != certInfo.Cert.Subject.String() {
				continue
			}

			err := crl.CheckSignatureFrom(certInfo.Cert)
			if err == nil {
				verified = true
				break
			}
		}

		if !verified {
			return false, nil
		}
	}

	return true, nil
}

type NotRevoked struct{}

func (NotRevoked) Name() string { return "notRevoked" }

func (NotRevoked) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	if len(ctx.CRLs) == 0 {
		return true, nil
	}

	cert := ctx.Cert.Cert
	certSerial := cert.SerialNumber.String()
	certIssuer := cert.Issuer.String()

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		if crl.Issuer.String() != certIssuer {
			continue
		}

		for _, revoked := range crl.RevokedCertificates {
			if revoked.SerialNumber != nil && revoked.SerialNumber.String() == certSerial {
				return false, nil
			}
		}
	}

	return true, nil
}
