package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/cavoq/PCL/internal/operator"
)

const committedSchemaPath = "../../schemas/policy.schema.json"

func compilePolicySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	generated, err := JSONSchema(operator.DefaultRegistry())
	if err != nil {
		t.Fatalf("JSONSchema: %v", err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(generated))
	if err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(SchemaID, document); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	schema, err := compiler.Compile(SchemaID)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

// yamlInstance decodes policy YAML into the JSON value the schema validates.
func yamlInstance(t *testing.T, data []byte) any {
	t.Helper()
	var decoded any
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return instance
}

func TestCommittedSchemaIsCurrent(t *testing.T) {
	generated, err := JSONSchema(operator.DefaultRegistry())
	if err != nil {
		t.Fatalf("JSONSchema: %v", err)
	}
	committed, err := os.ReadFile(committedSchemaPath)
	if err != nil {
		t.Fatalf("read committed schema: %v", err)
	}
	if !bytes.Equal(committed, generated) {
		t.Fatal("schemas/policy.schema.json is stale; run: go run ./cmd/pcl schema > schemas/policy.schema.json")
	}
}

func TestSchemaAcceptsRepositoryPolicies(t *testing.T) {
	schema := compilePolicySchema(t)
	var files []string
	for _, dir := range []string{"../../policies", "../../tests/policies"} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) < 20 {
		t.Fatalf("found only %d policy files", len(files))
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(yamlInstance(t, data)); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
}

func TestSchemaAndParserRejectTheSamePolicies(t *testing.T) {
	schema := compilePolicySchema(t)
	registry := operator.DefaultRegistry()
	tests := []struct {
		name   string
		policy string
		valid  bool
	}{
		{name: "descriptive metadata", valid: true, policy: `
id: example
metadata:
  title: Example profile
  standard: RFC 5280
  edition: "2008"
  source: https://www.rfc-editor.org/rfc/rfc5280
  description: Certificate profile and explicit path checks
  inputs: [certificate, issuers, trustAnchors, crl, ocsp, purpose, validationTime, psl]
rules: []`},
		{name: "empty metadata", valid: true, policy: `
id: example
metadata: {}`},
		{name: "numeric metadata edition", valid: true, policy: `
id: example
metadata: {edition: 2008}`},
		{name: "metadata text cannot be a list", policy: `
id: example
metadata: {description: [certificate]}`},
		{name: "unknown metadata field", policy: `
id: example
metadata: {trustAnchor: root.pem}`},
		{name: "unknown metadata input", policy: `
id: example
metadata: {inputs: [cert]}`},
		{name: "duplicate metadata input", policy: `
id: example
metadata: {inputs: [certificate, certificate]}`},
		{name: "metadata input whitespace", policy: `
id: example
metadata: {inputs: [" certificate"]}`},
		{name: "metadata must be a mapping", policy: `
id: example
metadata: [certificate]`},
		{name: "group with inherited fields", valid: true, policy: `
id: example
groups:
  - id: section
    reference: SPEC 1
    requirement: must
    certType: [leaf]
    effective: {basis: issuance, from: 2023-09-15}
    when: {target: certificate.extensions, operator: present}
    rules:
      - {id: r1, target: certificate.version, operator: present}`},
		{name: "group without rules", policy: `
id: example
groups:
  - {id: section, rules: []}`},
		{name: "unknown group field", policy: `
id: example
groups:
  - {id: section, severity: error, rules: [{id: r1, target: certificate.version, operator: present}]}`},
		{name: "compound condition", valid: true, policy: `
id: example
rules:
  - id: r1
    target: certificate.version
    operator: present
    severity: error
    when:
      allOf:
        - {target: certificate.extensions, operator: present}
        - not: {anyOf: [{target: certificate.subject, operator: absent}, {target: certificate.issuer, operator: absent}]}`},
		{name: "condition mixing forms", policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, severity: error, when: {target: a, operator: present, not: {target: b, operator: present}}}`},
		{name: "allOf with one condition", policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, severity: error, when: {allOf: [{target: a, operator: present}]}}`},
		{name: "profiles", valid: true, policy: `
id: example
profiles:
  - {id: tls-subordinate, title: TLS Subordinate CA, reference: SPEC 2, role: intermediate, when: {target: certificate.extKeyUsage.serverAuth, operator: eq, operands: [true]}}
  - {id: cross-certified, role: intermediate, assumeOnly: true}
rules:
  - {id: r1, target: certificate.version, operator: present, severity: error, profile: [tls-subordinate, cross-certified]}`},
		{name: "profile with an unknown role", policy: `
id: example
profiles: [{id: p, role: ca}]`},
		{name: "assumeOnly profile with a condition", policy: `
id: example
profiles: [{id: p, role: leaf, assumeOnly: true, when: {target: a, operator: present}}]`},
		{name: "effective window", valid: true, policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, severity: error, effective: {basis: issuance, from: 2026-03-15, until: "2027-03-15T00:00:00Z"}}`},
		{name: "effective without a bound", policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, severity: error, effective: {basis: issuance}}`},
		{name: "effective with an unknown basis", policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, severity: error, effective: {basis: issued, from: 2026-03-15}}`},
		{name: "requirement without severity", valid: true, policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, requirement: should}`},
		{name: "neither severity nor requirement", policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present}`},
		{name: "unknown requirement", policy: `
id: example
rules:
  - {id: r1, target: certificate.version, operator: present, requirement: shall}`},
		{name: "minimal", valid: true, policy: `
id: example
rules:
  - id: version-3
    target: certificate.version
    operator: eq
    operands: [3]
    severity: error`},
		{name: "scalar operand and condition", valid: true, policy: `
id: example
rules:
  - id: rsa-size
    target: certificate.subjectPublicKeyInfo.publicKey.keySize
    operator: gte
    operands: 2048
    severity: warning
    certType: [leaf]
    when:
      target: certificate.subjectPublicKeyInfo.algorithm.oid
      operator: eq
      operands: ["1.2.840.113549.1.1.1"]`},
		{name: "missing id", policy: `
rules: []`},
		{name: "unknown top-level field", policy: `
id: example
rule: []`},
		{name: "unknown operator", policy: `
id: example
rules:
  - {id: r, target: certificate.version, operator: equals, operands: [3], severity: error}`},
		{name: "invalid severity", policy: `
id: example
rules:
  - {id: r, target: certificate.version, operator: eq, operands: [3], severity: fatal}`},
		{name: "missing required operands", policy: `
id: example
rules:
  - {id: r, target: certificate.version, operator: eq, severity: error}`},
		{name: "operands for an operator without operands", policy: `
id: example
rules:
  - {id: r, target: certificate.version, operator: present, operands: [true], severity: error}`},
		{name: "non-numeric comparison operand", policy: `
id: example
rules:
  - {id: r, target: certificate.version, operator: gte, operands: ["3"], severity: error}`},
		{name: "unknown rule certType", policy: `
id: example
rules:
  - {id: r, target: certificate.version, operator: present, severity: error, certType: [server]}`},
		{name: "invalid condition operands", policy: `
id: example
rules:
  - id: r
    target: certificate.version
    operator: present
    severity: error
    when: {target: certificate.version, operator: maxLength, operands: [-1]}`},
		{name: "invalid appliesTo", policy: `
id: example
appliesTo: [certificate]
rules: []`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schemaErr := schema.Validate(yamlInstance(t, []byte(test.policy)))
			_, parseErr := ParseWithRegistry([]byte(test.policy), registry)
			if (schemaErr == nil) != test.valid {
				t.Errorf("schema error = %v, want valid %v", schemaErr, test.valid)
			}
			if (parseErr == nil) != test.valid {
				t.Errorf("parser error = %v, want valid %v", parseErr, test.valid)
			}
		})
	}
}
