package operator

import (
	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509node"
)

type PathLenValid struct{}

func (PathLenValid) Name() string { return "pathLenValid" }

func (PathLenValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil {
		return false, nil
	}
	return cert.PathLenConstraintValid(ctx.Cert, ctx.Chain), nil
}

type ValidityPeriodDays struct{}

func (ValidityPeriodDays) Name() string { return "validityDays" }

func (ValidityPeriodDays) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	duration := cert.NotAfter.Sub(cert.NotBefore)
	days := int(duration.Hours() / 24)

	if len(operands) < 2 {
		return false, nil
	}

	minDays, minErr := parseIntegerOperand(operands[0])
	maxDays, maxErr := parseIntegerOperand(operands[1])
	if minErr != nil || maxErr != nil {
		return false, nil
	}

	return days >= minDays && days <= maxDays, nil
}

type SerialNumberUnique struct{}

func (SerialNumberUnique) Name() string { return "serialNumberUnique" }

func (SerialNumberUnique) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	if cert.SerialNumber == nil {
		return false, nil
	}

	serialStr := cert.SerialNumber.String()
	position, inChain := ctx.ChainPosition()

	for i, other := range ctx.Chain {
		if inChain && i == position {
			continue
		}
		if other == nil || other.Cert == nil || other.Cert.SerialNumber == nil {
			continue
		}
		if x509asn1.NamesMatchOrText(cert.RawIssuer, other.Cert.RawIssuer, cert.Issuer.String(), other.Cert.Issuer.String()) {
			if other.Cert.SerialNumber.String() == serialStr {
				return false, nil
			}
		}
	}

	return true, nil
}

type ValidityOrderCorrect struct{}

func (ValidityOrderCorrect) Name() string { return "validityOrderCorrect" }

func (ValidityOrderCorrect) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	return cert.NotBefore.Before(cert.NotAfter), nil
}

type NoUnknownCriticalExtensions struct{}

func (NoUnknownCriticalExtensions) Name() string { return "noUnknownCriticalExtensions" }

func (NoUnknownCriticalExtensions) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	switch n.Name {
	case "certificate":
		return noUnknownCriticalExtensions(n, oid.ExtensionInCertificate), nil
	case "crl":
		if !noUnknownCriticalExtensions(n, oid.ExtensionInCRL) {
			return false, nil
		}
		revokedCertificates, _ := n.Resolve("revokedCertificates")
		for _, revokedCertificate := range node.CollectionElements(revokedCertificates) {
			if !noUnknownCriticalExtensions(revokedCertificate, oid.ExtensionInCRLEntry) {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, nil
	}
}

func noUnknownCriticalExtensions(n *node.Node, location oid.ExtensionLocation) bool {
	return x509node.CriticalExtensionsProcessable(n, location)
}
