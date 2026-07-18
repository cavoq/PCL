package asn1

import (
	"bytes"
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

func TestParseAlgorithmIDParams_ObjectIdentifierDecoding(t *testing.T) {
	tests := []struct {
		name string
		der  []byte
		want string
	}{
		{
			name: "multi-byte first subidentifier",
			der:  []byte{0x30, 0x05, 0x06, 0x03, 0x88, 0x37, 0x03}, // 2.999.3
			want: "2.999.3",
		},
		{
			name: "truncated base-128 component",
			der:  []byte{0x30, 0x04, 0x06, 0x02, 0x88, 0x80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseAlgorithmIDParams(tt.der).OID; got != tt.want {
				t.Fatalf("OID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSignedObjectAlgorithmParams(t *testing.T) {
	algorithmDER := []byte{
		0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
		0x05, 0x00,
	}
	content := append([]byte{0x30, 0x00}, algorithmDER...)
	content = append(content, 0x03, 0x01, 0x00)
	signedObject := append([]byte{0x30, byte(len(content))}, content...)

	got := ParseSignedObjectAlgorithmParams(signedObject)
	if got.OID != "1.2.840.113549.1.1.11" || !got.IsNull {
		t.Fatalf("unexpected AlgorithmIdentifier: %+v", got)
	}
	if !bytes.Equal(got.RawDER, algorithmDER) {
		t.Fatalf("raw DER = %x, want %x", got.RawDER, algorithmDER)
	}

	if got := ParseSignedObjectAlgorithmParams([]byte{0x30, 0x00}); got.OID != "" {
		t.Fatalf("malformed signed object produced AlgorithmIdentifier: %+v", got)
	}
}

func TestParseAlgorithmIDParamsStrict_DistinguishesAbsentAndMalformed(t *testing.T) {
	absentDER := []byte{
		0x30, 0x0b,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	}
	absent, err := ParseAlgorithmIDParamsStrict(absentDER)
	if err != nil {
		t.Fatalf("absent parameters rejected: %v", err)
	}
	if !absent.IsAbsent || absent.Malformed {
		t.Fatalf("absent parameters state = %+v", absent)
	}

	malformedDER := append(append([]byte(nil), absentDER...), 0x05, 0x00)
	if _, err := ParseAlgorithmIDParamsStrict(malformedDER); err == nil {
		t.Fatal("expected trailing DER to be rejected")
	}
	malformed := ParseAlgorithmIDParams(malformedDER)
	if !malformed.Malformed || malformed.IsAbsent {
		t.Fatalf("malformed parameters state = %+v", malformed)
	}
}

func TestParseAlgorithmIDParamsStrict_RejectsMalformedPSSField(t *testing.T) {
	// RSASSA-PSS AlgorithmIdentifier with [2] saltLength containing no INTEGER.
	der := []byte{
		0x30, 0x10,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
		0x30, 0x03, 0xa2, 0x01, 0x00,
	}
	if _, err := ParseAlgorithmIDParamsStrict(der); err == nil {
		t.Fatal("expected malformed PSS saltLength to be rejected")
	}
	if got := ParseAlgorithmIDParams(der); !got.Malformed {
		t.Fatalf("compatibility parser did not preserve malformed state: %+v", got)
	}
}
