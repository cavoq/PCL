package policy

import (
	"encoding/json"
	"sort"

	"github.com/cavoq/PCL/internal/operator"
)

// SchemaID is where the published policy schema is served from.
const SchemaID = "https://raw.githubusercontent.com/cavoq/PCL/master/schemas/policy.schema.json"

// JSONSchema returns the JSON Schema (draft-07) of policy files whose rules
// use the operators in registry. It mirrors the structural checks of Parse
// and each operator's operand contract, so editors can complete and check
// policies; ParseWithRegistry remains authoritative for semantic rules such
// as regular expression syntax or include resolution.
func JSONSchema(registry *operator.Registry) ([]byte, error) {
	names := registry.Names()
	definitions, operandRules := operandDefinitions(registry, names)
	operatorName := map[string]any{
		"type":        "string",
		"enum":        stringsToAny(names),
		"description": "Operator applied to the target node.",
	}
	definitions["condition"] = conditionSchema(operatorName, operandRules)
	definitions["rule"] = ruleSchema(operatorName, operandRules)

	schema := map[string]any{
		"$schema":              "http://json-schema.org/draft-07/schema#",
		"$id":                  SchemaID,
		"title":                "PCL policy",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"id"},
		"properties":           policyProperties(),
		"definitions":          definitions,
	}
	encoded, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// trimmedString is a nonempty string without surrounding whitespace.
var trimmedString = map[string]any{"type": "string", "pattern": `^\S(.*\S)?$`}

const targetDescription = "Dotted node path; list paths with pcl inspect --paths."

// operandDefinitions defines each shared operand contract once and returns
// the conditional rules applying them by operator name.
func operandDefinitions(registry *operator.Registry, names []string) (map[string]any, []any) {
	definitions := map[string]any{}
	groups := operandSchemaGroups(registry, names)
	operandRules := make([]any, 0, len(groups))
	for _, group := range groups {
		definition := "operands." + group.names[0]
		definitions[definition] = group.schema
		then := map[string]any{
			"properties": map[string]any{
				"operands": map[string]any{"$ref": "#/definitions/" + definition},
			},
		}
		if group.required {
			then["required"] = []any{"operands"}
		}
		operandRules = append(operandRules, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"operator": map[string]any{"enum": stringsToAny(group.names)}},
				"required":   []any{"operator"},
			},
			"then": then,
		})
	}
	return definitions, operandRules
}

func conditionSchema(operatorName map[string]any, operandRules []any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Evaluate the rule only when this condition holds.",
		"additionalProperties": false,
		"required":             []any{"target", "operator"},
		"properties": map[string]any{
			"target":   withSchemaDescription(trimmedString, targetDescription),
			"operator": operatorName,
			"operands": map[string]any{"description": "Operator operands: a sequence, or one value."},
		},
		"allOf": operandRules,
	}
}

func ruleSchema(operatorName map[string]any, operandRules []any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"id", "target", "operator", "severity"},
		"properties": map[string]any{
			"id":        withSchemaDescription(trimmedString, "Rule identifier, unique within the policy."),
			"reference": map[string]any{"type": "string", "description": "Specification reference, for example RFC 5280 4.2.1.9."},
			"target":    withSchemaDescription(trimmedString, targetDescription),
			"operator":  operatorName,
			"operands":  map[string]any{"description": "Operator operands: a sequence, or one value."},
			"severity":  map[string]any{"type": "string", "enum": setToAny(validSeverities)},
			"message":   map[string]any{"type": "string", "description": "Message reported when the rule fails."},
			"certType": map[string]any{
				"type":        "array",
				"uniqueItems": true,
				"items":       map[string]any{"type": "string", "enum": setToAny(validRuleCertTypes)},
				"description": "Evaluate the rule only for these roles; other roles skip it.",
			},
			"when": map[string]any{"$ref": "#/definitions/condition"},
		},
		"allOf": operandRules,
	}
}

func policyProperties() map[string]any {
	return map[string]any{
		"id":       withSchemaDescription(trimmedString, "Policy identifier."),
		"version":  map[string]any{"type": []any{"string", "number"}},
		"metadata": metadataSchema(),
		"includes": map[string]any{"type": "array", "uniqueItems": true, "items": trimmedString},
		"appliesTo": map[string]any{
			"type":        "array",
			"uniqueItems": true,
			"items":       map[string]any{"type": "string", "enum": setToAny(validInputTypes)},
			"description": "Inputs this policy is evaluated against; inferred from rule targets when omitted.",
		},
		"certType": map[string]any{
			"type":        "array",
			"uniqueItems": true,
			"items": map[string]any{"anyOf": []any{
				map[string]any{"type": "string", "enum": setToAny(validPolicyCertTypes)},
				map[string]any{"type": "string", "pattern": `^([01]\.([0-9]|[1-3][0-9])|2\.(0|[1-9][0-9]*))(\.(0|[1-9][0-9]*))*$`},
			}},
			"description": "Evaluate the policy only for these roles or extended key usage OIDs.",
		},
		"crlType": map[string]any{
			"type":        "array",
			"uniqueItems": true,
			"items":       map[string]any{"type": "string", "enum": setToAny(validCRLTypes)},
		},
		"tstType": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"sctType": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"rules":   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/definitions/rule"}},
	}
}

func metadataSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"description":          "Descriptive pack information only; does not configure validation or require inputs. Includes do not inherit metadata.",
		"properties": map[string]any{
			"title":       map[string]any{"type": "string"},
			"standard":    map[string]any{"type": "string"},
			"edition":     map[string]any{"type": []any{"string", "number"}},
			"source":      map[string]any{"type": "string", "description": "Source reference or URL; never fetched by the engine."},
			"description": map[string]any{"type": "string"},
			"inputs": map[string]any{
				"type":        "array",
				"uniqueItems": true,
				"items":       map[string]any{"type": "string", "enum": setToAny(validMetadataInputs)},
				"description": "Relevant evidence and runtime inputs; not a list of mandatory inputs or an execution filter.",
			},
		},
	}
}

type operandSchemaGroup struct {
	names    []string
	schema   map[string]any
	required bool
}

// operandSchemaGroups groups operators with identical operand contracts so
// the schema defines each contract once. Operands are required when the
// operator's validator rejects an empty operand list.
func operandSchemaGroups(registry *operator.Registry, names []string) []operandSchemaGroup {
	index := map[string]int{}
	var groups []operandSchemaGroup
	for _, name := range names {
		schema, ok := registry.OperandSchema(name)
		if !ok {
			continue
		}
		required := registry.Validate(name, nil) != nil
		encoded, err := json.Marshal(schema)
		if err != nil {
			continue
		}
		key := string(encoded)
		if required {
			key = "required:" + key
		}
		if position, seen := index[key]; seen {
			groups[position].names = append(groups[position].names, name)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, operandSchemaGroup{names: []string{name}, schema: schema, required: required})
	}
	return groups
}

func withSchemaDescription(schema map[string]any, description string) map[string]any {
	described := make(map[string]any, len(schema)+1)
	for key, value := range schema {
		described[key] = value
	}
	described["description"] = description
	return described
}

func stringsToAny(values []string) []any {
	converted := make([]any, len(values))
	for index, value := range values {
		converted[index] = value
	}
	return converted
}

func setToAny(set map[string]struct{}) []any {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return stringsToAny(values)
}
