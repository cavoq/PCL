package operator

import (
	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/node"
)

type EKUContains struct{}

func (EKUContains) Name() string { return "ekuContains" }

func (EKUContains) Evaluate(_ *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	if len(operands) == 0 {
		return false, nil
	}

	cert := ctx.Cert.Cert

	for _, op := range operands {
		ekuName, ok := op.(string)
		if !ok {
			continue
		}

		eku := parseEKU(ekuName)
		if eku == 0 {
			continue
		}

		found := false
		for _, certEKU := range cert.ExtKeyUsage {
			if certEKU == eku {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	return true, nil
}

type EKUNotContains struct{}

func (EKUNotContains) Name() string { return "ekuNotContains" }

func (EKUNotContains) Evaluate(_ *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	if len(operands) == 0 {
		return true, nil
	}

	cert := ctx.Cert.Cert

	for _, op := range operands {
		ekuName, ok := op.(string)
		if !ok {
			continue
		}

		eku := parseEKU(ekuName)
		if eku == 0 {
			continue
		}

		for _, certEKU := range cert.ExtKeyUsage {
			if certEKU == eku {
				return false, nil
			}
		}
	}

	return true, nil
}

type EKUServerAuth struct{}

func (EKUServerAuth) Name() string { return "ekuServerAuth" }

func (EKUServerAuth) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	// No EKU means any purpose is allowed
	if len(cert.ExtKeyUsage) == 0 {
		return true, nil
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true, nil
		}
	}

	return false, nil
}

type EKUClientAuth struct{}

func (EKUClientAuth) Name() string { return "ekuClientAuth" }

func (EKUClientAuth) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	// No EKU means any purpose is allowed
	if len(cert.ExtKeyUsage) == 0 {
		return true, nil
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
			return true, nil
		}
	}

	return false, nil
}

func parseEKU(name string) x509.ExtKeyUsage {
	switch name {
	case "any":
		return x509.ExtKeyUsageAny
	case "serverAuth":
		return x509.ExtKeyUsageServerAuth
	case "clientAuth":
		return x509.ExtKeyUsageClientAuth
	case "codeSigning":
		return x509.ExtKeyUsageCodeSigning
	case "emailProtection":
		return x509.ExtKeyUsageEmailProtection
	case "timeStamping":
		return x509.ExtKeyUsageTimeStamping
	case "ocspSigning":
		return x509.ExtKeyUsageOcspSigning
	default:
		return 0
	}
}
