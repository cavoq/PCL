package ocsp

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"testing"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
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

func TestReadBasicOCSPResponseValidatesResponseType(t *testing.T) {
	basicResponse := []byte{0x30, 0x00}
	basicType, err := oid.Parse(oid.OCSPBasicResponse)
	if err != nil {
		t.Fatal(err)
	}

	raw := marshalTestOCSPResponse(t, basicType, basicResponse)
	got, ok := readBasicOCSPResponse(raw)
	if !ok || !bytes.Equal(got, basicResponse) {
		t.Fatalf("readBasicOCSPResponse() = %x, %v; want %x, true", []byte(got), ok, basicResponse)
	}

	raw = marshalTestOCSPResponse(t, stdasn1.ObjectIdentifier{1, 2, 3, 4}, basicResponse)
	if _, ok := readBasicOCSPResponse(raw); ok {
		t.Fatal("readBasicOCSPResponse() accepted a non-basic response type")
	}
}

func marshalTestOCSPResponse(t *testing.T, responseType stdasn1.ObjectIdentifier, response []byte) []byte {
	t.Helper()
	responseTypeDER, err := x509asn1.EncodeObjectIdentifier(responseType)
	if err != nil {
		t.Fatalf("encode response type: %v", err)
	}
	responseBytes := x509asn1.EncodeSequence(append(responseTypeDER, x509asn1.EncodeOctetString(response)...))
	responseBytesOuter := x509asn1.EncodeContextSpecificConstructed(0, responseBytes)
	status := []byte{0x0a, 0x01, 0x00}
	return x509asn1.EncodeSequence(append(status, responseBytesOuter...))
}
