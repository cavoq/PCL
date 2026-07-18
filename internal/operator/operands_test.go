package operator

import (
	"math"
	"reflect"
	"testing"
)

func TestNormalizeOperands(t *testing.T) {
	structured := map[string]any{"key": "value"}
	tests := []struct {
		name  string
		input any
		want  []any
	}{
		{name: "nil", input: nil, want: nil},
		{name: "slice", input: []any{1, "two"}, want: []any{1, "two"}},
		{name: "structured map", input: structured, want: []any{structured}},
		{name: "scalar", input: "one", want: []any{"one"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalizeOperands(test.input); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("NormalizeOperands(%#v) = %#v, want %#v", test.input, got, test.want)
			}
		})
	}
}

func TestParseIntegerOperand(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		want    int
		wantErr bool
	}{
		{name: "int", value: 42, want: 42},
		{name: "int8", value: int8(8), want: 8},
		{name: "int64", value: int64(64), want: 64},
		{name: "uint32", value: uint32(32), want: 32},
		{name: "float32 integer", value: float32(3), want: 3},
		{name: "float64 integer", value: 4.0, want: 4},
		{name: "fraction", value: 3.9, wantErr: true},
		{name: "infinity", value: math.Inf(1), wantErr: true},
		{name: "string", value: "4", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseIntegerOperand(test.value)
			if test.wantErr && err == nil {
				t.Fatal("expected integer parsing error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected integer parsing error: %v", err)
			}
			if got != test.want {
				t.Fatalf("parseIntegerOperand(%v) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}
