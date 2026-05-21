package operator

import (
	crlpkg "github.com/cavoq/PCL/internal/crl"
	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
)

type CRLValid struct{}

func (CRLValid) Name() string { return "crlValid" }

func (CRLValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCRLs() {
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
	if !ctx.HasCRLs() {
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
	if !ctx.HasCRLs() {
		return false, nil
	}

	if !ctx.HasChain() {
		return false, nil
	}

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		var matchingIssuer *x509.Certificate
		for _, issuerInfo := range ctx.Chain {
			if issuerInfo.Cert == nil {
				continue
			}
			if crlpkg.CertSignsCRL(issuerInfo.Cert, crl) {
				matchingIssuer = issuerInfo.Cert
				break
			}
		}

		if matchingIssuer == nil {
			continue
		}

		if err := crl.CheckSignatureFrom(matchingIssuer); err != nil {
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

	cert := ctx.Cert.Cert
	certSerial := cert.SerialNumber.String()
	certIssuer := cert.Issuer.String()

	if !ctx.HasCRLs() {
		return true, nil // No CRLs = not revoked
	}

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