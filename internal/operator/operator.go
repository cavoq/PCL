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

// builtinOperator pairs a built-in operator with its operand contract. An
// empty contract means the operator implements OperandValidator and
// OperandSchemaProvider itself: Every and DateDiff need operator-specific
// parsing of structured operands (and, for Every, registry access to validate
// the nested invocation).
type builtinOperator struct {
	op       Operator
	contract operandContract
}

// builtins is the single catalog of built-in operators. Adding an operator
// here registers it in DefaultRegistry together with its operand contract.
var builtins = []builtinOperator{
	{Eq{}, oneOperandContract},
	{Neq{}, oneOperandContract},
	{Present{}, noOperandsContract},
	{Absent{}, noOperandsContract},
	{Gte{}, oneNumberContract},
	{Gt{}, oneNumberContract},
	{Lte{}, oneNumberContract},
	{Lt{}, oneNumberContract},
	{In{}, oneOrMoreContract},
	{NotIn{}, oneOrMoreContract},
	{Contains{}, oneOrMoreContract},
	{Before{}, optionalTimeContract},
	{After{}, optionalTimeContract},
	{OnOrBefore{}, optionalTimeContract},
	{OnOrAfter{}, optionalTimeContract},
	{Matches{}, nodePathsContract},
	{Positive{}, noOperandsContract},
	{Odd{}, noOperandsContract},
	{MultipleOf{}, positiveIntegerContract},
	{MaxLength{}, nonnegativeLengthContract},
	{MinLength{}, nonnegativeLengthContract},
	{IsCritical{}, noOperandsContract},
	{NotCritical{}, noOperandsContract},
	{IsEmpty{}, noOperandsContract},
	{NotEmpty{}, noOperandsContract},
	{Regex{}, oneRegexContract},
	{NotRegex{}, oneRegexContract},
	{SignatureValid{}, noOperandsContract},
	{IssuedBy{}, noOperandsContract},
	{AKIMatchesSKI{}, noOperandsContract},
	{PathLenValid{}, noOperandsContract},
	{PathValid{}, noOperandsContract},
	{ApplicationPurposeValid{}, noOperandsContract},
	{AnyExtendedKeyUsageNotCritical{}, noOperandsContract},
	{BasicConstraintsDependenciesValid{}, noOperandsContract},
	{KeyUsageDependenciesValid{}, noOperandsContract},
	{NameConstraintsDependenciesValid{}, noOperandsContract},
	{NameConstraintsDistancesValid{}, noOperandsContract},
	{CRLDistributionPointsDependenciesValid{}, noOperandsContract},
	{PolicyMappingsDependenciesValid{}, noOperandsContract},
	{PolicyMappingsIssuerPoliciesPresent{}, noOperandsContract},
	{PolicyConstraintsDependenciesValid{}, noOperandsContract},
	{InhibitAnyPolicyDependenciesValid{}, noOperandsContract},
	{ValidityPeriodDays{}, validityDaysContract},
	{ValidityOrderCorrect{}, noOperandsContract},
	{SignatureAlgorithmMatchesTBS{}, noOperandsContract},
	{NoUnknownCriticalExtensions{}, noOperandsContract},
	{EKUContains{}, ekusContract},
	{EKUNotContains{}, ekusContract},
	{EKUServerAuth{}, noOperandsContract},
	{EKUClientAuth{}, noOperandsContract},
	{SerialNumberUnique{}, noOperandsContract},
	{CRLValid{}, noOperandsContract},
	{CRLNotExpired{}, noOperandsContract},
	{CRLSignedBy{}, noOperandsContract},
	{NotRevoked{}, noOperandsContract},
	{NotRevokedByAvailableEvidence{}, noOperandsContract},
	{OCSPValid{}, noOperandsContract},
	{NotRevokedOCSP{}, noOperandsContract},
	{OCSPGood{}, noOperandsContract},
	// Generic operators
	{Every{}, operandContract{}},
	{AnyOf{}, operandContract{}},
	{DateDiff{}, operandContract{}},
	{NameConstraintsValid{}, noOperandsContract},
	{CertificatePolicyValid{}, policyOIDsContract},
	{IsNull{}, noOperandsContract},
	// Generic component validation operators (useful for DNS labels, path segments, etc.)
	{ComponentMaxLength{}, componentLengthContract},
	{ComponentMinLength{}, componentLengthContract},
	{ComponentRegex{}, componentRegexContract},
	{ComponentNotRegex{}, componentRegexContract},
	{AnyComponentMatches{}, oneRegexContract},
	{NoComponentMatches{}, oneRegexContract},
	// CIDR range validation operators (for IP address checking)
	{ComponentInCIDR{}, cidrsContract},
	{ComponentNotInCIDR{}, cidrsContract},
	// PSL/TLD validation operators (for domain name checking)
	{TLDRegistered{}, noOperandsContract},
	{TLDNotRegistered{}, noOperandsContract},
	{IsPublicSuffix{}, noOperandsContract},
	{IsNotPublicSuffix{}, noOperandsContract},
	{ComponentTLDNotRegistered{}, noOperandsContract},
	{ComponentIsPublicSuffix{}, noOperandsContract},
	{ComponentNotPublicSuffix{}, noOperandsContract},
	// UTF-8 validation operators
	{UTF8NoBOM{}, noOperandsContract},
	{ContainsBOM{}, noOperandsContract},
	// Subject DN validation operators
	{NoDuplicateAttributes{}, noOperandsContract},
	// Unique value operators (for AIA, CRL DP, etc.)
	{UniqueValues{}, noOperandsContract},
	{UniqueChildren{}, noOperandsContract},
	// Encoding validation operators (ASN.1)
	{IsIA5String{}, noOperandsContract},
	{IsPrintableString{}, noOperandsContract},
	{IsUTF8String{}, noOperandsContract},
	{ValidIA5String{}, noOperandsContract},
	{ValidPrintableString{}, noOperandsContract},
	// DER encoding validation (Mozilla byte-for-byte requirements)
	{DEREqualsHex{}, hexValuesContract},
}

// All lists the built-in operators in catalog order.
var All = func() []Operator {
	operators := make([]Operator, 0, len(builtins))
	for _, builtin := range builtins {
		operators = append(operators, builtin.op)
	}
	return operators
}()
