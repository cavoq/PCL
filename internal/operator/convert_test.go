package operator

import "testing"

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   float64
		wantOk bool
	}{
		{"int", 42, 42.0, true},
		{"int8", int8(8), 8.0, true},
		{"int16", int16(16), 16.0, true},
		{"int32", int32(32), 32.0, true},
		{"int64", int64(64), 64.0, true},
		{"uint", uint(10), 10.0, true},
		{"uint8", uint8(8), 8.0, true},
		{"uint16", uint16(16), 16.0, true},
		{"uint32", uint32(32), 32.0, true},
		{"uint64", uint64(64), 64.0, true},
		{"float32", float32(3.14), 3.14, true},
		{"float64", 3.14159, 3.14159, true},
		{"string", "hello", 0, false},
		{"nil", nil, 0, false},
		{"struct", struct{}{}, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ToFloat64(tt.input)
			if ok != tt.wantOk {
				t.Errorf("ToFloat64(%v) ok = %v, want %v", tt.input, ok, tt.wantOk)
			}
			if tt.wantOk && tt.name != "float32" {
				if got != tt.want {
					t.Errorf("ToFloat64(%v) = %v, want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestToInt(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   int
		wantOk bool
	}{
		{"int", 42, 42, true},
		{"int64", int64(64), 64, true},
		{"float64", 3.9, 3, true},
		{"string", "hello", 0, false},
		{"nil", nil, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ToInt(tt.input)
			if ok != tt.wantOk {
				t.Errorf("ToInt(%v) ok = %v, want %v", tt.input, ok, tt.wantOk)
			}
			if tt.wantOk && got != tt.want {
				t.Errorf("ToInt(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
