// Package operator provides rule operators for evaluating certificate field values.
package operator

import "github.com/cavoq/PCL/internal/node"

type Operator interface {
	Name() string
	Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error)
}

// OperandValidator is an optional operator capability for validating policy
// operands before evaluation. Operators that do not implement it remain valid,
// which preserves support for existing custom operators.
//
// The active registry is provided so composite operators can validate nested
// operator invocations against the same set of registered operators.
type OperandValidator interface {
	ValidateOperands(operands []any, registry *Registry) error
}

// OperandValidatorFunc adapts a validation function to OperandValidator. It is
// useful for sharing data-driven operand contracts across multiple operators.
type OperandValidatorFunc func(operands []any, registry *Registry) error

func (validate OperandValidatorFunc) ValidateOperands(operands []any, registry *Registry) error {
	return validate(operands, registry)
}

// RegistryAwareOperator is an optional operator capability for composite
// operators that need to invoke another operator. Registry.Evaluate supplies
// the active registry so nested evaluation honors custom registrations.
type RegistryAwareOperator interface {
	EvaluateWithRegistry(
		n *node.Node,
		ctx *EvaluationContext,
		operands []any,
		registry *Registry,
	) (bool, error)
}

// MissingTargetAware marks operators for which a missing node is meaningful
// input rather than an evaluation gap (for example, present and absent).
type MissingTargetAware interface {
	AcceptsMissingTarget()
}

var All = []Operator{
	Eq{},
	Neq{},
	Present{},
	Absent{},
	Gte{},
	Gt{},
	Lte{},
	Lt{},
	In{},
	NotIn{},
	Contains{},
	Before{},
	After{},
	OnOrBefore{},
	OnOrAfter{},
	Matches{},
	Positive{},
	Odd{},
	MaxLength{},
	MinLength{},
	IsCritical{},
	NotCritical{},
	IsEmpty{},
	NotEmpty{},
	Regex{},
	NotRegex{},
	SignatureValid{},
	IssuedBy{},
	AKIMatchesSKI{},
	PathLenValid{},
	ApplicationPurposeValid{},
	AnyExtendedKeyUsageNotCritical{},
	BasicConstraintsDependenciesValid{},
	KeyUsageDependenciesValid{},
	NameConstraintsDependenciesValid{},
	NameConstraintsDistancesValid{},
	CRLDistributionPointsDependenciesValid{},
	PolicyMappingsDependenciesValid{},
	PolicyMappingsIssuerPoliciesPresent{},
	PolicyConstraintsDependenciesValid{},
	InhibitAnyPolicyDependenciesValid{},
	ValidityPeriodDays{},
	ValidityOrderCorrect{},
	SignatureAlgorithmMatchesTBS{},
	NoUnknownCriticalExtensions{},
	EKUContains{},
	EKUNotContains{},
	EKUServerAuth{},
	EKUClientAuth{},
	SerialNumberUnique{},
	CRLValid{},
	CRLNotExpired{},
	CRLSignedBy{},
	NotRevoked{},
	OCSPValid{},
	NotRevokedOCSP{},
	OCSPGood{},
	// Generic operators
	Every{},
	DateDiff{},
	NameConstraintsValid{},
	CertificatePolicyValid{},
	IsNull{},
	// Generic component validation operators (useful for DNS labels, path segments, etc.)
	ComponentMaxLength{},
	ComponentMinLength{},
	ComponentRegex{},
	ComponentNotRegex{},
	AnyComponentMatches{},
	NoComponentMatches{},
	// CIDR range validation operators (for IP address checking)
	ComponentInCIDR{},
	ComponentNotInCIDR{},
	// PSL/TLD validation operators (for domain name checking)
	TLDRegistered{},
	TLDNotRegistered{},
	IsPublicSuffix{},
	IsNotPublicSuffix{},
	ComponentTLDNotRegistered{},
	ComponentIsPublicSuffix{},
	ComponentNotPublicSuffix{},
	// UTF-8 validation operators
	UTF8NoBOM{},
	ContainsBOM{},
	// Subject DN validation operators
	NoDuplicateAttributes{},
	// Unique value operators (for AIA, CRL DP, etc.)
	UniqueValues{},
	UniqueChildren{},
	// Encoding validation operators (ASN.1)
	IsIA5String{},
	IsPrintableString{},
	IsUTF8String{},
	ValidIA5String{},
	ValidPrintableString{},
	// DER encoding validation (Mozilla byte-for-byte requirements)
	DEREqualsHex{},
}
