package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

type operandValidationTestOperator struct {
	name string
}

func (op operandValidationTestOperator) Name() string { return op.name }

func (operandValidationTestOperator) Evaluate(
	_ *node.Node,
	_ *operator.EvaluationContext,
	_ []any,
) (bool, error) {
	return true, nil
}

func TestParseWithRegistryRejectsInvalidRuleOperands(t *testing.T) {
	tests := []struct {
		name       string
		operator   string
		operands   string
		wantDetail string
	}{
		{
			name:       "wrong arity",
			operator:   "eq",
			wantDetail: `operator "eq"`,
		},
		{
			name:       "wrong type",
			operator:   "gte",
			operands:   "    operands: [not-a-number]\n",
			wantDetail: `operator "gte"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := fmt.Sprintf(`
id: invalid-operands
rules:
  - id: invalid
    target: certificate.version
    operator: %s
%s    severity: error
`, tt.operator, tt.operands)

			_, err := ParseWithRegistry([]byte(data), operator.DefaultRegistry())
			if err == nil {
				t.Fatal("expected operand validation error")
			}
			if !strings.Contains(err.Error(), "rule invalid") ||
				!strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("error lacks rule/operator context: %v", err)
			}
		})
	}
}

func TestParseWithRegistryRejectsInvalidWhenOperands(t *testing.T) {
	_, err := ParseWithRegistry([]byte(`
id: invalid-condition-operands
rules:
  - id: conditional
    when:
      target: certificate.extensions
      operator: present
      operands: [true]
    target: certificate.version
    operator: present
    severity: error
`), operator.DefaultRegistry())
	if err == nil {
		t.Fatal("expected when operand validation error")
	}
	for _, want := range []string{"rule conditional", "when", `operator "present"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestParseWithRegistryAllowsCustomOperatorWithoutOperandValidator(t *testing.T) {
	registry := operator.NewRegistry()
	registry.Register(operandValidationTestOperator{name: "customWithoutValidator"})

	_, err := ParseWithRegistry([]byte(`
id: custom-operands
rules:
  - id: custom
    target: custom.value
    operator: customWithoutValidator
    operands:
      arbitrary: [true, 3, value]
    severity: error
`), registry)
	if err != nil {
		t.Fatalf("custom operator without validator was rejected: %v", err)
	}
}

func TestParseWithRegistryAddsContextToCustomOperandValidationError(t *testing.T) {
	registry := operator.NewRegistry()
	registry.RegisterValidated(
		operandValidationTestOperator{name: "customWithValidator"},
		operator.OperandValidatorFunc(func(_ []any, _ *operator.Registry) error {
			return errors.New("custom operands rejected")
		}),
	)

	_, err := ParseWithRegistry([]byte(`
id: custom-invalid-operands
rules:
  - id: custom-invalid
    target: custom.value
    operator: customWithValidator
    operands: [anything]
    severity: error
`), registry)
	if err == nil {
		t.Fatal("expected custom operand validation error")
	}
	for _, want := range []string{
		"rule custom-invalid",
		`operator "customWithValidator"`,
		"custom operands rejected",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestParseDirWithRegistryRejectsInvalidOperands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yaml")
	data := []byte(`
id: invalid-directory-policy
rules:
  - id: invalid-directory-rule
    target: certificate.version
    operator: gte
    operands: [not-a-number]
    severity: error
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ParseDirWithRegistry(dir, operator.DefaultRegistry())
	if err == nil || !strings.Contains(err.Error(), "invalid-directory-rule") {
		t.Fatalf("directory operand validation error = %v", err)
	}
}

func TestParseFileWithRegistryRejectsInvalidIncludedOperands(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child.yaml")
	parent := filepath.Join(dir, "parent.yaml")
	if err := os.WriteFile(child, []byte(`
id: child
rules:
  - id: invalid-included-rule
    target: certificate.version
    operator: present
    operands: [unexpected]
    severity: error
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte(`
id: parent
includes: [child.yaml]
rules: []
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ParseFileWithRegistry(parent, operator.DefaultRegistry())
	if err == nil || !strings.Contains(err.Error(), "invalid-included-rule") {
		t.Fatalf("included operand validation error = %v", err)
	}
}
