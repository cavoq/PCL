package asn1

import (
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestOIDString(t *testing.T) {
	tests := []struct {
		name     string
		oidBytes []byte
		expected string
	}{
		{
			name:     "sha256WithRSAEncryption",
			oidBytes: []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b},
			expected: "1.2.840.113549.1.1.11",
		},
		{
			name:     "rsaEncryption",
			oidBytes: []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01},
			expected: "1.2.840.113549.1.1.1",
		},
		{
			name:     "commonName",
			oidBytes: []byte{0x55, 0x04, 0x03},
			expected: "2.5.4.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := oidString(tt.oidBytes)
			if result != tt.expected {
				t.Errorf("got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestReadOIDComponent(t *testing.T) {
	oid := cryptobyte.String([]byte{0x86, 0x48})
	var got int
	if !readOIDComponent(&oid, &got) {
		t.Fatal("expected OID component to parse")
	}
	if got != 840 {
		t.Fatalf("expected 840, got %d", got)
	}
}
