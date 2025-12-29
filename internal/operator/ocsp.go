package operator

import (
	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/zcrypto"
)

type OCSPValid struct{}

func (OCSPValid) Name() string { return "ocspValid" }

func (OCSPValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasOCSPs() || !ctx.HasChain() {
		return false, nil
	}

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}
		resp := ocspInfo.Response

		if ctx.Now.Before(resp.ThisUpdate) {
			return false, nil
		}
		if !resp.NextUpdate.IsZero() && ctx.Now.After(resp.NextUpdate) {
			return false, nil
		}

		verified := false
		for _, certInfo := range ctx.Chain {
			if certInfo.Cert == nil {
				continue
			}
			stdCert, err := zcrypto.ToStdCert(certInfo.Cert)
			if err != nil || stdCert == nil {
				continue
			}
			if resp.CheckSignatureFrom(stdCert) == nil {
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

type NotRevokedOCSP struct{}

func (NotRevokedOCSP) Name() string { return "notRevokedOCSP" }

func (NotRevokedOCSP) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}

	if len(ctx.OCSPs) == 0 {
		return true, nil
	}

	certSerial := ctx.Cert.Cert.SerialNumber.String()

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}
		resp := ocspInfo.Response

		if resp.SerialNumber == nil || resp.SerialNumber.String() != certSerial {
			continue
		}

		if resp.Status == ocsp.Revoked {
			return false, nil
		}
	}

	return true, nil
}

type OCSPGood struct{}

func (OCSPGood) Name() string { return "ocspGood" }

func (OCSPGood) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}

	if len(ctx.OCSPs) == 0 {
		return false, nil
	}

	certSerial := ctx.Cert.Cert.SerialNumber.String()

	for _, ocspInfo := range ctx.OCSPs {
		if ocspInfo.Response == nil {
			continue
		}
		resp := ocspInfo.Response

		if resp.SerialNumber == nil || resp.SerialNumber.String() != certSerial {
			continue
		}

		if resp.Status == ocsp.Good {
			return true, nil
		}
	}

	return false, nil
}
