package asn1

import (
	"testing"
)

func TestParseAlgorithmIDParams(t *testing.T) {
	tests := []struct {
		name     string
		der      []byte
		expected ParamsState
	}{
		{
			name: "RSA with NULL parameters",
			// SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }
			der: []byte{
				0x30, 0x0d, // SEQUENCE, length 13
				0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // OID sha256WithRSAEncryption
				0x05, 0x00, // NULL
			},
			expected: ParamsState{
				OID:    "1.2.840.113549.1.1.11",
				IsNull: true,
			},
		},
		{
			name: "RSA with absent parameters",
			// SEQUENCE { OID 1.2.840.113549.1.1.11 } (no parameters)
			der: []byte{
				0x30, 0x0b, // SEQUENCE, length 11
				0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // OID
			},
			expected: ParamsState{
				OID:      "1.2.840.113549.1.1.11",
				IsAbsent: true,
			},
		},
		{
			name: "RSA encryption OID",
			// SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
			der: []byte{
				0x30, 0x0d, // SEQUENCE, length 13
				0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
				0x05, 0x00, // NULL
			},
			expected: ParamsState{
				OID:    "1.2.840.113549.1.1.1",
				IsNull: true,
			},
		},
		{
			name:     "Invalid DER",
			der:      []byte{0x00, 0x00},
			expected: ParamsState{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseAlgorithmIDParams(tt.der)
			if result.OID != tt.expected.OID {
				t.Errorf("OID: got %s, want %s", result.OID, tt.expected.OID)
			}
			if result.IsNull != tt.expected.IsNull {
				t.Errorf("IsNull: got %v, want %v", result.IsNull, tt.expected.IsNull)
			}
			if result.IsAbsent != tt.expected.IsAbsent {
				t.Errorf("IsAbsent: got %v, want %v", result.IsAbsent, tt.expected.IsAbsent)
			}
		})
	}
}
