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

// builtinOperator pairs a built-in operator with its operand contract. A nil
// validate function means the operator implements OperandValidator itself:
// Every and DateDiff need operator-specific parsing of structured operands
// (and, for Every, registry access to validate the nested invocation).
type builtinOperator struct {
	op       Operator
	validate OperandValidatorFunc
}

// builtins is the single catalog of built-in operators. Adding an operator
// here registers it in DefaultRegistry together with its operand contract.
var builtins = []builtinOperator{
	{Eq{}, validateOneOperand},
	{Neq{}, validateOneOperand},
	{Present{}, validateNoOperands},
	{Absent{}, validateNoOperands},
	{Gte{}, validateOneNumber},
	{Gt{}, validateOneNumber},
	{Lte{}, validateOneNumber},
	{Lt{}, validateOneNumber},
	{In{}, validateOneOrMoreOperands},
	{NotIn{}, validateOneOrMoreOperands},
	{Contains{}, validateOneOrMoreOperands},
	{Before{}, validateOptionalTime},
	{After{}, validateOptionalTime},
	{OnOrBefore{}, validateOptionalTime},
	{OnOrAfter{}, validateOptionalTime},
	{Matches{}, validateNodePaths},
	{Positive{}, validateNoOperands},
	{Odd{}, validateNoOperands},
	{MaxLength{}, validateNonnegativeLength},
	{MinLength{}, validateNonnegativeLength},
	{IsCritical{}, validateNoOperands},
	{NotCritical{}, validateNoOperands},
	{IsEmpty{}, validateNoOperands},
	{NotEmpty{}, validateNoOperands},
	{Regex{}, validateOneRegex},
	{NotRegex{}, validateOneRegex},
	{SignatureValid{}, validateNoOperands},
	{IssuedBy{}, validateNoOperands},
	{AKIMatchesSKI{}, validateNoOperands},
	{PathLenValid{}, validateNoOperands},
	{ApplicationPurposeValid{}, validateNoOperands},
	{AnyExtendedKeyUsageNotCritical{}, validateNoOperands},
	{BasicConstraintsDependenciesValid{}, validateNoOperands},
	{KeyUsageDependenciesValid{}, validateNoOperands},
	{NameConstraintsDependenciesValid{}, validateNoOperands},
	{NameConstraintsDistancesValid{}, validateNoOperands},
	{CRLDistributionPointsDependenciesValid{}, validateNoOperands},
	{PolicyMappingsDependenciesValid{}, validateNoOperands},
	{PolicyMappingsIssuerPoliciesPresent{}, validateNoOperands},
	{PolicyConstraintsDependenciesValid{}, validateNoOperands},
	{InhibitAnyPolicyDependenciesValid{}, validateNoOperands},
	{ValidityPeriodDays{}, validateValidityDays},
	{ValidityOrderCorrect{}, validateNoOperands},
	{SignatureAlgorithmMatchesTBS{}, validateNoOperands},
	{NoUnknownCriticalExtensions{}, validateNoOperands},
	{EKUContains{}, validateEKUs},
	{EKUNotContains{}, validateEKUs},
	{EKUServerAuth{}, validateNoOperands},
	{EKUClientAuth{}, validateNoOperands},
	{SerialNumberUnique{}, validateNoOperands},
	{CRLValid{}, validateNoOperands},
	{CRLNotExpired{}, validateNoOperands},
	{CRLSignedBy{}, validateNoOperands},
	{NotRevoked{}, validateNoOperands},
	{NotRevokedByAvailableEvidence{}, validateNoOperands},
	{OCSPValid{}, validateNoOperands},
	{NotRevokedOCSP{}, validateNoOperands},
	{OCSPGood{}, validateNoOperands},
	// Generic operators
	{Every{}, nil},
	{DateDiff{}, nil},
	{NameConstraintsValid{}, validateNoOperands},
	{CertificatePolicyValid{}, validatePolicyOIDs},
	{IsNull{}, validateNoOperands},
	// Generic component validation operators (useful for DNS labels, path segments, etc.)
	{ComponentMaxLength{}, validateComponentLength},
	{ComponentMinLength{}, validateComponentLength},
	{ComponentRegex{}, validateComponentRegexOperands},
	{ComponentNotRegex{}, validateComponentRegexOperands},
	{AnyComponentMatches{}, validateOneRegex},
	{NoComponentMatches{}, validateOneRegex},
	// CIDR range validation operators (for IP address checking)
	{ComponentInCIDR{}, validateCIDRs},
	{ComponentNotInCIDR{}, validateCIDRs},
	// PSL/TLD validation operators (for domain name checking)
	{TLDRegistered{}, validateNoOperands},
	{TLDNotRegistered{}, validateNoOperands},
	{IsPublicSuffix{}, validateNoOperands},
	{IsNotPublicSuffix{}, validateNoOperands},
	{ComponentTLDNotRegistered{}, validateNoOperands},
	{ComponentIsPublicSuffix{}, validateNoOperands},
	{ComponentNotPublicSuffix{}, validateNoOperands},
	// UTF-8 validation operators
	{UTF8NoBOM{}, validateNoOperands},
	{ContainsBOM{}, validateNoOperands},
	// Subject DN validation operators
	{NoDuplicateAttributes{}, validateNoOperands},
	// Unique value operators (for AIA, CRL DP, etc.)
	{UniqueValues{}, validateNoOperands},
	{UniqueChildren{}, validateNoOperands},
	// Encoding validation operators (ASN.1)
	{IsIA5String{}, validateNoOperands},
	{IsPrintableString{}, validateNoOperands},
	{IsUTF8String{}, validateNoOperands},
	{ValidIA5String{}, validateNoOperands},
	{ValidPrintableString{}, validateNoOperands},
	// DER encoding validation (Mozilla byte-for-byte requirements)
	{DEREqualsHex{}, validateHexValues},
}

// All lists the built-in operators in catalog order.
var All = func() []Operator {
	operators := make([]Operator, 0, len(builtins))
	for _, builtin := range builtins {
		operators = append(operators, builtin.op)
	}
	return operators
}()
