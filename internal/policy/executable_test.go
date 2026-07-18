package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

type policyTestOperator struct{}

func (policyTestOperator) Name() string { return "customPolicyOperator" }

func (policyTestOperator) Evaluate(
	_ *node.Node,
	_ *operator.EvaluationContext,
	_ []any,
) (bool, error) {
	return true, nil
}

func TestValidateExecutable_RejectsUnknownOperators(t *testing.T) {
	tests := []struct {
		name        string
		operator    string
		when        string
		wantMessage string
	}{
		{
			name:        "rule operator",
			operator:    "typo",
			wantMessage: `unknown operator "typo"`,
		},
		{
			name:        "condition operator",
			operator:    "present",
			when:        "    when:\n      target: certificate.extensions\n      operator: typo\n",
			wantMessage: `when: unknown operator "typo"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := "id: test-policy\nrules:\n" +
				"  - id: r1\n" + tt.when +
				"    target: certificate.version\n" +
				"    operator: " + tt.operator + "\n" +
				"    severity: error\n"
			parsed, err := Parse([]byte(data))
			if err != nil {
				t.Fatalf("structural parse rejected operator name: %v", err)
			}
			err = ValidateExecutable(parsed, operator.DefaultRegistry())
			if err == nil || !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("expected error containing %q, got %v", tt.wantMessage, err)
			}
		})
	}
}

func TestParseWithRegistry_AllowsCustomOperator(t *testing.T) {
	registry := operator.NewRegistry()
	registry.Register(policyTestOperator{})

	parsed, err := ParseWithRegistry([]byte(`
id: test-policy
rules:
  - id: custom
    target: custom.value
    operator: customPolicyOperator
    severity: error
`), registry)
	if err != nil {
		t.Fatalf("custom registry rejected: %v", err)
	}
	if parsed.Rules[0].Operator != "customPolicyOperator" {
		t.Fatalf("operator = %q", parsed.Rules[0].Operator)
	}
}

func TestValidateExecutable_RequiresRegistry(t *testing.T) {
	err := ValidateExecutable(Policy{ID: "test"}, nil)
	if err == nil || !strings.Contains(err.Error(), "operator registry is required") {
		t.Fatalf("expected missing registry error, got %v", err)
	}
}

func TestValidateExecutable_DelegatesOperandValidation(t *testing.T) {
	registry := operator.NewRegistry()
	registry.RegisterValidated(policyTestOperator{}, operator.OperandValidatorFunc(
		func(operands []any, _ *operator.Registry) error {
			if len(operands) == 1 && operands[0] == "invalid" {
				return fmt.Errorf("operand must not be invalid")
			}
			return nil
		},
	))

	tests := []struct {
		name string
		when string
		body string
		want string
	}{
		{
			name: "rule operands",
			body: "    operands: [invalid]\n",
			want: `rule custom: operator "customPolicyOperator": operand must not be invalid`,
		},
		{
			name: "condition operands",
			when: "    when:\n      target: custom.enabled\n      operator: customPolicyOperator\n      operands: [invalid]\n",
			want: `rule custom: when: operator "customPolicyOperator": operand must not be invalid`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse([]byte("id: test-policy\nrules:\n" +
				"  - id: custom\n" + test.when +
				"    target: custom.value\n" +
				"    operator: customPolicyOperator\n" + test.body +
				"    severity: error\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			err = ValidateExecutable(parsed, registry)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateExecutable() error = %v, want context %q", err, test.want)
			}
		})
	}
}
