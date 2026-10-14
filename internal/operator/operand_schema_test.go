package operator

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// compileOperandSchema compiles one operator's operand schema as a
// standalone draft-07 document.
func compileOperandSchema(t *testing.T, registry *Registry, name string) *jsonschema.Schema {
	t.Helper()
	schema, ok := registry.OperandSchema(name)
	if !ok {
		t.Fatalf("operator %q has no operand schema", name)
	}
	document := map[string]any{"$schema": "http://json-schema.org/draft-07/schema#"}
	for key, value := range schema {
		document[key] = value
	}
	decoded := decodeJSONValue(t, document)
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("operands.json", decoded); err != nil {
		t.Fatalf("add %q schema: %v", name, err)
	}
	compiled, err := compiler.Compile("operands.json")
	if err != nil {
		t.Fatalf("compile %q schema: %v", name, err)
	}
	return compiled
}

// decodeJSONValue converts a Go value to the representation the schema
// validator expects, failing for values JSON cannot carry.
func decodeJSONValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %#v: %v", value, err)
	}
	decoded, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("unmarshal %s: %v", encoded, err)
	}
	return decoded
}

// operandsValue is the YAML operands value that normalizes to operands; nil
// stands for an absent or null operands field.
func operandsValue(operands []any) any {
	if operands == nil {
		return nil
	}
	return operands
}

// representable reports whether JSON can carry the operands (NaN cannot).
func representable(operands []any) bool {
	_, err := json.Marshal(operands)
	return err == nil
}

func TestOperandSchemasAgreeWithValidators(t *testing.T) {
	registry := DefaultRegistry()
	for _, test := range operandContractCases {
		t.Run(test.name, func(t *testing.T) {
			schema := compileOperandSchema(t, registry, test.operator)
			for _, operands := range test.valid {
				if !representable(operands) {
					continue
				}
				if err := schema.Validate(decodeJSONValue(t, operandsValue(operands))); err != nil {
					t.Errorf("schema rejects valid operands %#v: %v", operands, err)
				}
			}
			for _, operands := range test.invalid {
				if !representable(operands) {
					continue
				}
				if err := schema.Validate(decodeJSONValue(t, operandsValue(operands))); err == nil {
					t.Errorf("schema accepts invalid operands %#v", operands)
				}
			}
			for _, operands := range test.semanticInvalid {
				if err := schema.Validate(decodeJSONValue(t, operandsValue(operands))); err != nil {
					t.Errorf("schema rejects structurally valid operands %#v: %v", operands, err)
				}
			}
		})
	}
}

// TestOperandSchemaExamples checks scalar shorthand and structured operands
// against both the JSON Schema and the Go validator.
func TestOperandSchemaExamples(t *testing.T) {
	registry := DefaultRegistry()
	tests := []struct {
		operator string
		operands any
		valid    bool
	}{
		{"eq", 3, true},
		{"eq", map[string]any{"key": "value"}, true},
		{"gte", 2048, true},
		{"gte", "2048", false},
		{"in", "serverAuth", true},
		{"regex", "^[a-z]+$", true},
		{"maxLength", 63, true},
		{"componentMaxLength", 63, true},
		{"present", true, false},
		{"present", []any{}, true},
		{"before", "now", true},
		// Structured operands.
		{"every", map[string]any{"path": "value", "operator": "maxLength", "operands": []any{64}}, true},
		{"every", map[string]any{"check": "present"}, true},
		{"every", []any{"value", "present"}, true},
		{"every", map[string]any{"path": "value"}, false},
		{"every", map[string]any{"operator": "present", "unknown": true}, false},
		{"every", map[string]any{"operator": "present", "skipMissing": "yes"}, false},
		{"dateDiff", map[string]any{"start": "thisUpdate", "end": "nextUpdate", "maxDays": 10}, true},
		{"dateDiff", map[string]any{"from": "notBefore", "maxMonths": 13}, true},
		{"dateDiff", map[string]any{"start": "thisUpdate"}, false},
		{"dateDiff", map[string]any{"end": "nextUpdate", "maxDays": 10}, false},
		{"dateDiff", map[string]any{"start": "thisUpdate", "maxDays": 0}, false},
		{"dateDiff", map[string]any{"start": "thisUpdate", "maxDays": 10, "extra": 1}, false},
	}
	for _, test := range tests {
		err := compileOperandSchema(t, registry, test.operator).Validate(decodeJSONValue(t, test.operands))
		if (err == nil) != test.valid {
			t.Errorf("%s operands %#v: schema error = %v, want valid %v", test.operator, test.operands, err, test.valid)
		}
		if goErr := registry.Validate(test.operator, NormalizeOperands(test.operands)); (goErr == nil) != test.valid {
			t.Errorf("%s operands %#v: validator error = %v, want valid %v", test.operator, test.operands, goErr, test.valid)
		}
	}
}

func TestRegistryOperandSchemas(t *testing.T) {
	registry := DefaultRegistry()
	names := registry.Names()
	if len(names) != len(All) {
		t.Fatalf("Names() has %d entries, want %d", len(names), len(All))
	}
	for _, name := range names {
		if _, ok := registry.OperandSchema(name); !ok {
			t.Errorf("built-in operator %q has no operand schema", name)
		}
	}

	custom := NewRegistry()
	custom.RegisterValidated(Eq{}, OperandValidatorFunc(func([]any, *Registry) error { return nil }))
	if _, ok := custom.OperandSchema("eq"); ok {
		t.Error("a replaced validator must drop the built-in operand schema")
	}
}
