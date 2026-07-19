package operator

import (
	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
)

type ApplicationPurposeValid struct{}

func (ApplicationPurposeValid) Name() string { return "applicationPurposeValid" }

func (ApplicationPurposeValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if ctx == nil {
		return false, nil
	}
	return cert.ApplicationPurposeValid(ctx.Cert, ctx.ApplicationPurpose), nil
}

type AnyExtendedKeyUsageNotCritical struct{}

func (AnyExtendedKeyUsageNotCritical) Name() string {
	return "anyExtendedKeyUsageNotCritical"
}

func (AnyExtendedKeyUsageNotCritical) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.AnyExtendedKeyUsageNotCritical(ctx.Cert.Cert), nil
}

type BasicConstraintsDependenciesValid struct{}

func (BasicConstraintsDependenciesValid) Name() string {
	return "basicConstraintsDependenciesValid"
}

func (BasicConstraintsDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.BasicConstraintsDependenciesValid(ctx.Cert.Cert), nil
}

type KeyUsageDependenciesValid struct{}

func (KeyUsageDependenciesValid) Name() string { return "keyUsageDependenciesValid" }

func (KeyUsageDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.KeyUsageDependenciesValid(ctx.Cert.Cert), nil
}

type NameConstraintsDependenciesValid struct{}

func (NameConstraintsDependenciesValid) Name() string {
	return "nameConstraintsDependenciesValid"
}

func (NameConstraintsDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.NameConstraintsDependenciesValid(ctx.Cert.Cert), nil
}

type NameConstraintsDistancesValid struct{}

func (NameConstraintsDistancesValid) Name() string { return "nameConstraintsDistancesValid" }

func (NameConstraintsDistancesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.NameConstraintsDistancesValid(ctx.Cert.Cert), nil
}

type CRLDistributionPointsDependenciesValid struct{}

func (CRLDistributionPointsDependenciesValid) Name() string {
	return "crlDistributionPointsDependenciesValid"
}

func (CRLDistributionPointsDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.CRLDistributionPointsDependenciesValid(ctx.Cert.Cert), nil
}

type PolicyMappingsDependenciesValid struct{}

func (PolicyMappingsDependenciesValid) Name() string {
	return "policyMappingsDependenciesValid"
}

func (PolicyMappingsDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.PolicyMappingsDependenciesValid(ctx.Cert.Cert), nil
}

type PolicyMappingsIssuerPoliciesPresent struct{}

func (PolicyMappingsIssuerPoliciesPresent) Name() string {
	return "policyMappingsIssuerPoliciesPresent"
}

func (PolicyMappingsIssuerPoliciesPresent) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.PolicyMappingsIssuerPoliciesPresent(ctx.Cert.Cert), nil
}

type PolicyConstraintsDependenciesValid struct{}

func (PolicyConstraintsDependenciesValid) Name() string {
	return "policyConstraintsDependenciesValid"
}

func (PolicyConstraintsDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.PolicyConstraintsDependenciesValid(ctx.Cert.Cert), nil
}

type InhibitAnyPolicyDependenciesValid struct{}

func (InhibitAnyPolicyDependenciesValid) Name() string {
	return "inhibitAnyPolicyDependenciesValid"
}

func (InhibitAnyPolicyDependenciesValid) Evaluate(
	_ *node.Node,
	ctx *EvaluationContext,
	_ []any,
) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}
	return cert.InhibitAnyPolicyDependenciesValid(ctx.Cert.Cert), nil
}
