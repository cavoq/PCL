package operator

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
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
	for i := range position {
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

	minDays, minErr := parseIntegerOperand(operands[0])
	maxDays, maxErr := parseIntegerOperand(operands[1])
	if minErr != nil || maxErr != nil {
		return false, nil
	}

	return days >= minDays && days <= maxDays, nil
}

type SANRequiredIfEmptySubject struct{}

func (SANRequiredIfEmptySubject) Name() string { return "sanRequiredIfEmptySubject" }

func (SANRequiredIfEmptySubject) Evaluate(n *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil || ctx.Cert == nil || ctx.Cert.Cert == nil {
		return false, nil
	}

	cert := ctx.Cert.Cert
	if len(cert.Subject.Names) > 0 {
		return true, nil
	}

	if n == nil {
		return false, nil
	}
	san, found := n.Resolve("subjectAltName")
	if !found || san == nil {
		return false, nil
	}
	count, ok := san.Value.(int)
	return ok && count > 0, nil
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
		return noUnknownCriticalExtensions(n, knownCertificateExtensionOIDs), nil
	case "crl":
		return noUnknownCriticalExtensions(n, knownCRLExtensionOIDs), nil
	default:
		return false, nil
	}
}

func noUnknownCriticalExtensions(n *node.Node, known map[string]struct{}) bool {
	extsNode, _ := n.Resolve("extensions")
	if extsNode == nil {
		return true
	}

	seen := make(map[*node.Node]struct{}, len(extsNode.Children))
	for _, extNode := range extsNode.Children {
		if extNode == nil {
			continue
		}
		if _, duplicate := seen[extNode]; duplicate {
			continue
		}
		seen[extNode] = struct{}{}

		criticalNode, _ := extNode.Resolve("critical")
		if criticalNode == nil {
			continue
		}

		critical, ok := criticalNode.Value.(bool)
		if !ok || !critical {
			continue
		}

		oidNode, _ := extNode.Resolve("oid")
		if oidNode == nil {
			return false
		}
		oidValue, ok := oidNode.Value.(string)
		if !ok {
			return false
		}
		if _, ok := known[oidValue]; !ok {
			return false
		}
	}

	return true
}

var knownCertificateExtensionOIDs = oidSet(
	oid.SubjectDirectoryAttributes,
	oid.SubjectKeyIdentifier,
	oid.KeyUsage,
	oid.PrivateKeyUsagePeriod,
	oid.SubjectAlternativeName,
	oid.IssuerAlternativeName,
	oid.BasicConstraints,
	oid.NameConstraints,
	oid.CRLDistributionPoints,
	oid.CertificatePolicies,
	oid.PolicyMappings,
	oid.AuthorityKeyIdentifier,
	oid.PolicyConstraints,
	oid.ExtendedKeyUsage,
	oid.FreshestCRL,
	oid.InhibitAnyPolicy,
	oid.AuthorityInfoAccess,
	oid.SubjectInfoAccess,
)

var knownCRLExtensionOIDs = oidSet(
	oid.AuthorityKeyIdentifier,
	oid.IssuerAlternativeName,
	oid.CRLNumber,
	oid.DeltaCRLIndicator,
	oid.IssuingDistributionPoint,
	oid.FreshestCRL,
	oid.AuthorityInfoAccess,
)

func oidSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
