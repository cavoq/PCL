package operator

import (
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/cavoq/PCL/internal/oid"
)

// builtinOperandValidationGroup keeps operand contracts next to the built-in
// operator catalog without making policy parsing aware of individual
// operators. Every and DateDiff validate themselves because their structured
// operands need operator-specific parsing (and, for Every, registry access).
type builtinOperandValidationGroup struct {
	operators []Operator
	validator OperandValidatorFunc
}

var builtinOperandValidationCatalog = []builtinOperandValidationGroup{
	{
		operators: []Operator{
			Present{}, Absent{}, Positive{}, Odd{}, IsCritical{}, NotCritical{},
			IsEmpty{}, NotEmpty{}, SignatureValid{}, IssuedBy{}, AKIMatchesSKI{},
			PathLenValid{}, ValidityOrderCorrect{}, SignatureAlgorithmMatchesTBS{},
			NoUnknownCriticalExtensions{}, SANRequiredIfEmptySubject{}, KeyUsageCA{},
			KeyUsageLeaf{}, EKUServerAuth{}, EKUClientAuth{}, NoUniqueIdentifiers{},
			SerialNumberUnique{}, CRLValid{}, CRLNotExpired{}, CRLSignedBy{},
			NotRevoked{}, OCSPValid{}, NotRevokedOCSP{}, OCSPGood{},
			NameConstraintsValid{}, IsNull{}, TLDRegistered{}, TLDNotRegistered{},
			IsPublicSuffix{}, IsNotPublicSuffix{}, ComponentTLDRegistered{},
			ComponentTLDNotRegistered{}, ComponentIsPublicSuffix{},
			ComponentNotPublicSuffix{}, UTF8NoBOM{}, ContainsBOM{},
			NoDuplicateAttributes{}, UniqueValues{}, UniqueChildren{},
			UTCTimeHasZulu{}, UTCTimeHasSeconds{}, GeneralizedTimeHasZulu{},
			GeneralizedTimeNoFraction{}, IsUTCTime{}, IsGeneralizedTime{},
			IsIA5String{}, IsPrintableString{}, IsUTF8String{}, ValidIA5String{},
			ValidPrintableString{},
		},
		validator: validateNoOperands,
	},
	{
		operators: []Operator{Eq{}, Neq{}},
		validator: validateOneOperand,
	},
	{
		operators: []Operator{Gte{}, Gt{}, Lte{}, Lt{}},
		validator: validateOneNumber,
	},
	{
		operators: []Operator{In{}, NotIn{}, Contains{}},
		validator: validateOneOrMoreOperands,
	},
	{
		operators: []Operator{Before{}, After{}, OnOrBefore{}, OnOrAfter{}},
		validator: validateOptionalTime,
	},
	{
		operators: []Operator{Matches{}},
		validator: validateNodePaths,
	},
	{
		operators: []Operator{MaxLength{}, MinLength{}},
		validator: validateNonnegativeLength,
	},
	{
		operators: []Operator{Regex{}, NotRegex{}, AnyComponentMatches{}, NoComponentMatches{}},
		validator: validateOneRegex,
	},
	{
		operators: []Operator{ValidityPeriodDays{}},
		validator: validateValidityDays,
	},
	{
		operators: []Operator{EKUContains{}, EKUNotContains{}},
		validator: validateEKUs,
	},
	{
		operators: []Operator{CertificatePolicyValid{}},
		validator: validatePolicyOIDs,
	},
	{
		operators: []Operator{ComponentMaxLength{}, ComponentMinLength{}},
		validator: validateComponentLength,
	},
	{
		operators: []Operator{ComponentRegex{}, ComponentNotRegex{}},
		validator: validateComponentRegexOperands,
	},
	{
		operators: []Operator{ComponentInCIDR{}, ComponentNotInCIDR{}},
		validator: validateCIDRs,
	},
	{
		operators: []Operator{DEREqualsHex{}},
		validator: validateHexValues,
	},
}

var builtinOperandValidatorsByType = func() map[reflect.Type]OperandValidator {
	validators := make(map[reflect.Type]OperandValidator)
	for _, group := range builtinOperandValidationCatalog {
		for _, op := range group.operators {
			validators[reflect.TypeOf(op)] = group.validator
		}
	}
	return validators
}()

// builtinOperandValidator resolves contracts by concrete built-in type. A
// custom operator may intentionally reuse a built-in name without inheriting
// a schema that belongs to a different implementation.
func builtinOperandValidator(op Operator) (OperandValidator, bool) {
	typeOf := reflect.TypeOf(op)
	if typeOf == nil {
		return nil, false
	}
	if typeOf.Kind() == reflect.Pointer {
		typeOf = typeOf.Elem()
	}
	validator, ok := builtinOperandValidatorsByType[typeOf]
	return validator, ok
}

// unvalidatedBuiltinOperators is an invariant helper for keeping All and the
// operand catalog in sync. An operator-provided validator is included in the
// registry by Register, so composite and catalog-driven contracts are treated
// uniformly here.
func unvalidatedBuiltinOperators(registry *Registry) []string {
	if registry == nil {
		return []string{"<nil registry>"}
	}

	missing := make([]string, 0)
	for _, op := range All {
		name := op.Name()
		if _, registered := registry.ops[name]; !registered {
			missing = append(missing, name+" (not registered)")
			continue
		}
		if _, validated := registry.validators[name]; !validated {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func validateNoOperands(operands []any, _ *Registry) error {
	return validateOperandCount(operands, 0, 0)
}

func validateOneOperand(operands []any, _ *Registry) error {
	return validateOperandCount(operands, 1, 1)
}

func validateOneOrMoreOperands(operands []any, _ *Registry) error {
	return validateOperandCount(operands, 1, -1)
}

func validateOneNumber(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, 1); err != nil {
		return err
	}
	if _, ok := numericValue(operands[0]); !ok {
		return fmt.Errorf("operand 0 must be a finite number")
	}
	return nil
}

func validateNonnegativeLength(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, 1); err != nil {
		return err
	}
	value, err := parseIntegerOperand(operands[0])
	if err != nil {
		return fmt.Errorf("operand 0: %w", err)
	}
	if value < 0 {
		return fmt.Errorf("operand 0 must be nonnegative")
	}
	return nil
}

func validateOptionalTime(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 0, 1); err != nil {
		return err
	}
	if len(operands) == 0 {
		return nil
	}
	if err := validateTimeValue(operands[0]); err != nil {
		return fmt.Errorf("operand 0: %w", err)
	}
	return nil
}

func validateNodePaths(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, -1); err != nil {
		return err
	}
	for index, operand := range operands {
		path, ok := operand.(string)
		if !ok || strings.TrimSpace(path) == "" {
			return fmt.Errorf("operand %d must be a nonempty node path", index)
		}
		if strings.TrimSpace(path) != path {
			return fmt.Errorf("operand %d node path must not have surrounding whitespace", index)
		}
	}
	return nil
}

func validateOneRegex(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, 1); err != nil {
		return err
	}
	return validateRegexValue(operands[0], 0)
}

func validateValidityDays(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 2, 2); err != nil {
		return err
	}

	minimum, err := parseIntegerOperand(operands[0])
	if err != nil {
		return fmt.Errorf("operand 0: %w", err)
	}
	maximum, err := parseIntegerOperand(operands[1])
	if err != nil {
		return fmt.Errorf("operand 1: %w", err)
	}
	if minimum < 0 || maximum < 0 {
		return fmt.Errorf("validity day bounds must be nonnegative")
	}
	if minimum > maximum {
		return fmt.Errorf("minimum validity days must not exceed maximum validity days")
	}
	return nil
}

func validateEKUs(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, -1); err != nil {
		return err
	}
	for index, operand := range operands {
		name, ok := operand.(string)
		if !ok {
			return fmt.Errorf("operand %d must be an EKU name", index)
		}
		if _, ok := parseEKU(name); !ok {
			return fmt.Errorf("operand %d contains unsupported EKU %q", index, name)
		}
	}
	return nil
}

func validatePolicyOIDs(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, -1); err != nil {
		return err
	}
	for index, operand := range operands {
		value, ok := operand.(string)
		if !ok || !oid.ValidDotted(value) {
			return fmt.Errorf("operand %d must be a valid dotted OID", index)
		}
	}
	return nil
}

func validateComponentLength(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, 2); err != nil {
		return err
	}
	length, err := parseIntegerOperand(operands[0])
	if err != nil {
		return fmt.Errorf("operand 0: %w", err)
	}
	if length < 0 {
		return fmt.Errorf("operand 0 must be nonnegative")
	}
	return validateOptionalDelimiter(operands)
}

func validateComponentRegexOperands(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, 2); err != nil {
		return err
	}
	if err := validateRegexValue(operands[0], 0); err != nil {
		return err
	}
	return validateOptionalDelimiter(operands)
}

func validateOptionalDelimiter(operands []any) error {
	if len(operands) < 2 {
		return nil
	}
	delimiter, ok := operands[1].(string)
	if !ok || delimiter == "" {
		return fmt.Errorf("operand 1 must be a nonempty delimiter string")
	}
	return nil
}

func validateCIDRs(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, -1); err != nil {
		return err
	}
	for index, operand := range operands {
		value, ok := operand.(string)
		if !ok {
			return fmt.Errorf("operand %d must be a CIDR string", index)
		}
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("operand %d is not a valid CIDR: %w", index, err)
		}
	}
	return nil
}

func validateHexValues(operands []any, _ *Registry) error {
	if err := validateOperandCount(operands, 1, -1); err != nil {
		return err
	}
	for index, operand := range operands {
		value, ok := operand.(string)
		if !ok || value == "" {
			return fmt.Errorf("operand %d must be a nonempty hexadecimal string", index)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("operand %d is not valid hexadecimal: %w", index, err)
		}
	}
	return nil
}

func validateOperandCount(operands []any, minimum, maximum int) error {
	count := len(operands)
	if count < minimum || (maximum >= 0 && count > maximum) {
		switch {
		case minimum == maximum:
			return fmt.Errorf("requires exactly %d operands, got %d", minimum, count)
		case maximum < 0:
			return fmt.Errorf("requires at least %d operands, got %d", minimum, count)
		default:
			return fmt.Errorf("requires between %d and %d operands, got %d", minimum, maximum, count)
		}
	}
	return nil
}

func validateRegexValue(value any, index int) error {
	pattern, ok := value.(string)
	if !ok {
		return fmt.Errorf("operand %d must be a regular expression string", index)
	}
	if _, err := getCompiledRegex(pattern); err != nil {
		return fmt.Errorf("operand %d is not a valid regular expression: %w", index, err)
	}
	return nil
}

func validateTimeValue(value any) error {
	if text, ok := value.(string); ok && text == "now" {
		return nil
	}
	if _, err := toTime(value); err != nil {
		return err
	}
	return nil
}
