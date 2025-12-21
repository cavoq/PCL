package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

type PathLenValid struct{}

func (PathLenValid) Name() string { return "pathLenValid" }

func (PathLenValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	if ctx.Cert.Type == "root" {
		return true, nil
	}

	position := ctx.Cert.Position
	cert := ctx.Cert.Cert

	caBelowCount := 0
	for i := 0; i < position; i++ {
		if i < len(ctx.Chain) && ctx.Chain[i] != nil && ctx.Chain[i].Cert != nil {
			if ctx.Chain[i].Cert.IsCA {
				caBelowCount++
			}
		}
	}

	for i := position + 1; i < len(ctx.Chain); i++ {
		issuer := ctx.Chain[i]
		if issuer == nil || issuer.Cert == nil {
			continue
		}

		if issuer.Cert.MaxPathLen >= 0 || issuer.Cert.MaxPathLenZero {
			maxPath := issuer.Cert.MaxPathLen
			casBetween := 0
			for j := 0; j < i; j++ {
				if ctx.Chain[j] != nil && ctx.Chain[j].Cert != nil && ctx.Chain[j].Cert.IsCA {
					casBetween++
				}
			}
			if casBetween > maxPath {
				return false, nil
			}
		}
	}

	if cert.IsCA && (cert.MaxPathLen >= 0 || cert.MaxPathLenZero) {
		if caBelowCount > cert.MaxPathLen {
			return false, nil
		}
	}

	return true, nil
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

	minDays, ok1 := toInt(operands[0])
	maxDays, ok2 := toInt(operands[1])
	if !ok1 || !ok2 {
		return false, nil
	}

	return days >= minDays && days <= maxDays, nil
}

type SANRequiredIfEmptySubject struct{}

func (SANRequiredIfEmptySubject) Name() string { return "sanRequiredIfEmptySubject" }

func (SANRequiredIfEmptySubject) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	subjectEmpty := len(cert.Subject.Country) == 0 &&
		len(cert.Subject.Organization) == 0 &&
		len(cert.Subject.OrganizationalUnit) == 0 &&
		cert.Subject.CommonName == "" &&
		len(cert.Subject.Locality) == 0 &&
		len(cert.Subject.Province) == 0 &&
		cert.Subject.SerialNumber == ""

	if !subjectEmpty {
		return true, nil
	}

	hasSAN := len(cert.DNSNames) > 0 ||
		len(cert.EmailAddresses) > 0 ||
		len(cert.IPAddresses) > 0 ||
		len(cert.URIs) > 0

	return hasSAN, nil
}

type KeyUsageCA struct{}

func (KeyUsageCA) Name() string { return "keyUsageCA" }

func (KeyUsageCA) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	if !cert.IsCA {
		return true, nil
	}

	const keyCertSign = 1 << 5
	return cert.KeyUsage&keyCertSign != 0, nil
}

type KeyUsageLeaf struct{}

func (KeyUsageLeaf) Name() string { return "keyUsageLeaf" }

func (KeyUsageLeaf) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert

	if cert.IsCA {
		return true, nil
	}

	const keyCertSign = 1 << 5
	return cert.KeyUsage&keyCertSign == 0, nil
}

type NoUniqueIdentifiers struct{}

func (NoUniqueIdentifiers) Name() string { return "noUniqueIdentifiers" }

func (NoUniqueIdentifiers) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	hasIssuerUID := cert.IssuerUniqueId.BitLength > 0
	hasSubjectUID := cert.SubjectUniqueId.BitLength > 0

	return !hasIssuerUID && !hasSubjectUID, nil
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

	for i, other := range ctx.Chain {
		if i == ctx.Cert.Position {
			continue
		}
		if other == nil || other.Cert == nil || other.Cert.SerialNumber == nil {
			continue
		}
		if cert.Issuer.String() == other.Cert.Issuer.String() {
			if other.Cert.SerialNumber.String() == serialStr {
				return false, nil
			}
		}
	}

	return true, nil
}
