package zcrypto

import (
	"testing"
)

func TestParseNonceFromRaw(t *testing.T) {
	// Test with empty input
	result := ParseNonceFromRaw([]byte{})
	if result.Present {
		t.Error("Expected nonce.Present=false for empty input")
	}

	// Test with invalid ASN.1
	result = ParseNonceFromRaw([]byte{0x00, 0x01, 0x02})
	if result.Present {
		t.Error("Expected nonce.Present=false for invalid ASN.1")
	}
}

func TestNonceOIDString(t *testing.T) {
	// Test OID string conversion
	expected := "1.3.6.1.5.5.7.48.1.2"
	if nonceOID != expected {
		t.Errorf("Expected nonceOID=%s, got %s", expected, nonceOID)
	}
}
