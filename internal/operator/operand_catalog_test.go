package operator

import (
	"math"
	"slices"
	"testing"
	"time"
)

func TestBuiltinOperandCatalogContracts(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAll(All)

	tests := []struct {
		name     string
		operator string
		valid    [][]any
		invalid  [][]any
	}{
		{
			name:     "no operands",
			operator: "present",
			valid:    [][]any{nil},
			invalid:  [][]any{{true}},
		},
		{
			name:     "one arbitrary operand",
			operator: "eq",
			valid:    [][]any{{true}, {map[string]any{"key": "value"}}},
			invalid:  [][]any{nil, {1, 2}},
		},
		{
			name:     "one finite number",
			operator: "gte",
			valid:    [][]any{{1}, {int64(2)}, {2.5}},
			invalid:  [][]any{nil, {"1"}, {math.NaN()}, {1, 2}},
		},
		{
			name:     "one or more arbitrary operands",
			operator: "in",
			valid:    [][]any{{1}, {1, "two", true}},
			invalid:  [][]any{nil},
		},
		{
			name:     "optional comparison time",
			operator: "before",
			valid: [][]any{
				nil,
				{"now"},
				{"2026-07-18"},
				{"2026-07-18T12:30:00+02:00"},
				{time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)},
			},
			invalid: [][]any{{17}, {"tomorrow"}, {"now", "now"}},
		},
		{
			name:     "node paths",
			operator: "matches",
			valid:    [][]any{{"certificate.issuer"}, {"certificate.issuer", "certificate.subject"}},
			invalid:  [][]any{nil, {""}, {" certificate.issuer"}, {42}},
		},
		{
			name:     "nonnegative length",
			operator: "maxLength",
			valid:    [][]any{{0}, {int64(63)}, {63.0}},
			invalid:  [][]any{nil, {-1}, {1.5}, {"63"}, {1, 2}},
		},
		{
			name:     "regular expression",
			operator: "regex",
			valid:    [][]any{{""}, {"^[a-z]+$"}},
			invalid:  [][]any{nil, {"["}, {42}, {"a", "b"}},
		},
		{
			name:     "validity day range",
			operator: "validityDays",
			valid:    [][]any{{0, 398}, {int64(1), 365.0}},
			invalid:  [][]any{nil, {1}, {-1, 10}, {11, 10}, {1.5, 10}, {1, 2, 3}},
		},
		{
			name:     "extended key usages",
			operator: "ekuContains",
			valid:    [][]any{{"serverAuth"}, {"clientAuth", "ocspSigning"}},
			invalid:  [][]any{nil, {"unknown"}, {17}},
		},
		{
			name:     "certificate policy OIDs",
			operator: "certificatePolicyValid",
			valid:    [][]any{{"2.5.29.32.0"}, {"1.3.6.1.5.5.7.14.2", "2.23.140.1.2.1"}},
			invalid:  [][]any{nil, {""}, {"3.1"}, {"1.40"}, {"1.03.6"}, {17}},
		},
		{
			name:     "component length and delimiter",
			operator: "componentMaxLength",
			valid:    [][]any{{63}, {63, "."}, {0, "/"}},
			invalid:  [][]any{nil, {-1}, {63, ""}, {63, 1}, {63, ".", "extra"}},
		},
		{
			name:     "component regex and delimiter",
			operator: "componentRegex",
			valid:    [][]any{{"^[a-z]+$"}, {"^[a-z]+$", "."}},
			invalid:  [][]any{nil, {"["}, {"ok", ""}, {"ok", 1}, {"ok", ".", "extra"}},
		},
		{
			name:     "CIDR list",
			operator: "componentInCIDR",
			valid:    [][]any{{"10.0.0.0/8"}, {"10.0.0.0/8", "2001:db8::/32"}},
			invalid:  [][]any{nil, {"10.0.0.1"}, {"10.0.0.0/8", "invalid"}, {17}},
		},
		{
			name:     "DER hex list",
			operator: "derEqualsHex",
			valid:    [][]any{{"00"}, {"3000", "deadbeef"}},
			invalid:  [][]any{nil, {""}, {"0"}, {"zz"}, {"00", 17}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, operands := range test.valid {
				if err := registry.Validate(test.operator, operands); err != nil {
					t.Errorf("Validate(%q, %#v) returned error: %v", test.operator, operands, err)
				}
			}
			for _, operands := range test.invalid {
				if err := registry.Validate(test.operator, operands); err == nil {
					t.Errorf("Validate(%q, %#v) unexpectedly succeeded", test.operator, operands)
				}
			}
		})
	}
}

func TestBuiltinOperandCatalogHasNoDuplicateOperators(t *testing.T) {
	seen := make(map[string]struct{})
	for _, group := range builtinOperandValidationCatalog {
		if group.validator == nil {
			t.Fatal("catalog contains a nil validator")
		}
		for _, op := range group.operators {
			name := op.Name()
			if _, duplicate := seen[name]; duplicate {
				t.Errorf("operator %q occurs in more than one operand validation group", name)
			}
			seen[name] = struct{}{}
		}
	}

	for _, composite := range []string{"every", "dateDiff"} {
		if _, cataloged := seen[composite]; cataloged {
			t.Errorf("composite operator %q should provide its own operand validator", composite)
		}
	}
}

func TestAllBuiltinOperatorsHaveOperandValidators(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAll(All)

	if missing := unvalidatedBuiltinOperators(registry); len(missing) != 0 {
		t.Fatalf("built-in operators without operand validators: %v", missing)
	}
}

func TestUnvalidatedBuiltinOperatorsReportsMissingContract(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAll(All)
	delete(registry.validators, "eq")

	missing := unvalidatedBuiltinOperators(registry)
	if !slices.Contains(missing, "eq") {
		t.Fatalf("missing validators = %v, want eq", missing)
	}
}
