package operator

import (
	"sort"

	"github.com/cavoq/PCL/internal/oid"
)

// OperandSchemaProvider is an optional operator capability describing the
// YAML operands value as a JSON Schema (draft-07) fragment. Editors use it to
// complete and check policies; Validate remains the authoritative check,
// including semantic rules a schema cannot express.
type OperandSchemaProvider interface {
	OperandSchema() map[string]any
}

// operandContract pairs a built-in operand validator with the JSON Schema of
// the operands value it accepts.
type operandContract struct {
	validate OperandValidatorFunc
	schema   map[string]any
}

// Operand values in YAML: a sequence is the operand list, a scalar or a
// mapping is a single operand (see NormalizeOperands).

var notListOrNull = map[string]any{"not": map[string]any{"type": []any{"array", "null"}}}

// operandList accepts between minimum and maximum operands matching item,
// written as a sequence or, when one operand is allowed, as a single value.
// A negative maximum is unbounded.
func operandList(item map[string]any, minimum, maximum int) map[string]any {
	list := map[string]any{"type": "array", "items": item, "minItems": minimum}
	if maximum >= 0 {
		list["maxItems"] = maximum
	}
	alternatives := []any{list}
	if minimum <= 1 && (maximum < 0 || maximum >= 1) {
		alternatives = append(alternatives, map[string]any{"allOf": []any{item, notListOrNull}})
	}
	if minimum == 0 {
		alternatives = append(alternatives, map[string]any{"type": "null"})
	}
	return map[string]any{"anyOf": alternatives}
}

// operandTuple accepts positional operands where the first required are
// mandatory, written as a sequence or, for a single operand, as a value.
func operandTuple(required int, items ...map[string]any) map[string]any {
	positional := make([]any, len(items))
	for index, item := range items {
		positional[index] = item
	}
	tuple := map[string]any{
		"type":            "array",
		"items":           positional,
		"additionalItems": false,
		"minItems":        required,
		"maxItems":        len(items),
	}
	alternatives := []any{tuple}
	if required <= 1 {
		alternatives = append(alternatives, map[string]any{"allOf": []any{items[0], notListOrNull}})
	}
	return map[string]any{"anyOf": alternatives}
}

func withDescription(schema map[string]any, description string) map[string]any {
	schema["description"] = description
	return schema
}

var (
	anyOperand         = map[string]any{}
	numberOperand      = map[string]any{"type": "number"}
	stringOperand      = map[string]any{"type": "string"}
	nonnegativeInteger = map[string]any{"type": "integer", "minimum": 0}
	delimiterOperand   = map[string]any{"type": "string", "minLength": 1}
	// trimmedString is a nonempty string without surrounding whitespace.
	trimmedString = map[string]any{"type": "string", "pattern": `^\S(.*\S)?$`}
	timeOperand   = map[string]any{
		"type":    "string",
		"pattern": `^(now|\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2}))?)$`,
	}
	dottedOIDOperand = map[string]any{
		"type":    "string",
		"pattern": `^([01]\.([0-9]|[1-3][0-9])|2\.(0|[1-9][0-9]*))(\.(0|[1-9][0-9]*))*$`,
	}
	cidrOperand = map[string]any{"type": "string", "pattern": `^[0-9A-Fa-f:.]+/[0-9]{1,3}$`}
	hexOperand  = map[string]any{"type": "string", "pattern": `^([0-9A-Fa-f]{2})+$`}
)

func ekuOperand() map[string]any {
	names := oid.ExtKeyUsageNames()
	sort.Strings(names)
	enum := make([]any, len(names))
	for index, name := range names {
		enum[index] = name
	}
	return map[string]any{"type": "string", "enum": enum}
}

var (
	noOperandsContract = operandContract{validateNoOperands, withDescription(
		map[string]any{"type": []any{"array", "null"}, "maxItems": 0}, "Takes no operands.")}
	oneOperandContract = operandContract{validateOneOperand, withDescription(
		operandList(anyOperand, 1, 1), "Exactly one value.")}
	oneNumberContract = operandContract{validateOneNumber, withDescription(
		operandList(numberOperand, 1, 1), "Exactly one number.")}
	oneOrMoreContract = operandContract{validateOneOrMoreOperands, withDescription(
		operandList(anyOperand, 1, -1), "One or more values.")}
	optionalTimeContract = operandContract{validateOptionalTime, withDescription(
		operandList(timeOperand, 0, 1),
		`Optional comparison time: "now", YYYY-MM-DD or RFC 3339; defaults to the evaluation time.`)}
	nodePathsContract = operandContract{validateNodePaths, withDescription(
		operandList(trimmedString, 1, -1), "One or more node paths.")}
	nonnegativeLengthContract = operandContract{validateNonnegativeLength, withDescription(
		operandList(nonnegativeInteger, 1, 1), "A nonnegative length.")}
	positiveIntegerContract = operandContract{validatePositiveInteger, withDescription(
		operandList(map[string]any{"type": "integer", "minimum": 1}, 1, 1), "A positive integer.")}
	oneRegexContract = operandContract{validateOneRegex, withDescription(
		operandList(stringOperand, 1, 1), "One Go regular expression.")}
	validityDaysContract = operandContract{validateValidityDays, withDescription(
		operandTuple(2, nonnegativeInteger, nonnegativeInteger), "Minimum and maximum validity in days.")}
	ekusContract = operandContract{validateEKUs, withDescription(
		operandList(ekuOperand(), 1, -1), "One or more extended key usage names.")}
	policyOIDsContract = operandContract{validatePolicyOIDs, withDescription(
		operandList(dottedOIDOperand, 0, -1),
		"Acceptable certificate policy OIDs; none applies the RFC 5280 default policy inputs.")}
	componentLengthContract = operandContract{validateComponentLength, withDescription(
		operandTuple(1, nonnegativeInteger, delimiterOperand), `Length bound and optional delimiter (default ".").`)}
	componentRegexContract = operandContract{validateComponentRegexOperands, withDescription(
		operandTuple(1, stringOperand, delimiterOperand), `Go regular expression and optional delimiter (default ".").`)}
	cidrsContract = operandContract{validateCIDRs, withDescription(
		operandList(cidrOperand, 1, -1), "One or more CIDR ranges.")}
	hexValuesContract = operandContract{validateHexValues, withDescription(
		operandList(hexOperand, 1, -1), "One or more hex-encoded DER values.")}
)

// OperandSchema describes the object and positional forms of every operands.
func (Every) OperandSchema() map[string]any {
	object := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"path":        map[string]any{"type": "string", "description": "Path below each element; * matches every element of a collection."},
			"operator":    map[string]any{"type": "string", "minLength": 1, "description": "Operator applied to each element."},
			"check":       map[string]any{"type": "string", "minLength": 1, "description": "Legacy alias of operator."},
			"operands":    map[string]any{"description": "Operands of the inner operator."},
			"values":      map[string]any{"description": "Legacy alias of operands."},
			"skipMissing": map[string]any{"type": "boolean", "description": "Skip elements where path does not resolve."},
		},
		"anyOf": []any{
			map[string]any{"required": []any{"operator"}},
			map[string]any{"required": []any{"check"}},
		},
	}
	positional := map[string]any{
		"type":     "array",
		"items":    []any{map[string]any{"type": "string"}, map[string]any{"type": "string", "minLength": 1}},
		"minItems": 2,
	}
	return withDescription(map[string]any{"anyOf": []any{
		object,
		map[string]any{"type": "array", "items": object, "minItems": 1, "maxItems": 1},
		positional,
	}}, "Inner operator applied to every element of a collection.")
}

// OperandSchema describes the dateDiff duration object.
func (DateDiff) OperandSchema() map[string]any {
	positive := map[string]any{"type": "integer", "minimum": 1}
	bounds := []string{"maxDays", "maxMonths", "minDays", "minHours", "maxHours"}
	properties := map[string]any{
		"start": map[string]any{"type": "string", "minLength": 1, "description": "Path of the start date below the target."},
		"from":  map[string]any{"type": "string", "minLength": 1, "description": "Legacy alias of start."},
		"end":   map[string]any{"type": "string", "minLength": 1, "description": "Path of the end date; defaults to the target's own value."},
		"inclusive": map[string]any{
			"type":        "boolean",
			"description": "Count the end second, as an RFC 5280 validity period does: the duration is end - start + 1s.",
		},
	}
	anyBound := make([]any, 0, len(bounds))
	for _, bound := range bounds {
		properties[bound] = positive
		anyBound = append(anyBound, map[string]any{"required": []any{bound}})
	}
	object := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
		"allOf": []any{
			map[string]any{"anyOf": []any{
				map[string]any{"required": []any{"start"}},
				map[string]any{"required": []any{"from"}},
			}},
			map[string]any{"anyOf": anyBound},
		},
	}
	return withDescription(map[string]any{"anyOf": []any{
		object,
		map[string]any{"type": "array", "items": object, "minItems": 1, "maxItems": 1},
	}}, "Duration bounds between two dates.")
}
