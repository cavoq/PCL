package ocsp

import (
	"bytes"
	"crypto"
	"testing"

	der "github.com/cavoq/PCL/internal/asn1"
)

func TestGenerateNonce(t *testing.T) {
	nonce, err := generateNonce(32)
	if err != nil {
		t.Errorf("Failed to generate nonce: %v", err)
	}
	if len(nonce) != 32 {
		t.Errorf("Expected nonce length 32, got %d", len(nonce))
	}
}

func TestParseNonceHex(t *testing.T) {
	hexValue := "aabbccdd12345678"
	nonce, err := parseNonceHex(hexValue)
	if err != nil {
		t.Errorf("Failed to parse nonce hex: %v", err)
	}
	expected := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x12, 0x34, 0x56, 0x78}
	if !bytes.Equal(nonce, expected) {
		t.Errorf("Expected %v, got %v", expected, nonce)
	}
}

func TestCertIDHash(t *testing.T) {
	hash, name := certIDHash(nil)
	if hash != crypto.SHA256 || name != "SHA256" {
		t.Fatalf("expected SHA256 default, got %v %s", hash, name)
	}

	hash, name = certIDHash(&NonceOptions{Hash: "sha1"})
	if hash != crypto.SHA1 || name != "SHA1" {
		t.Fatalf("expected SHA1, got %v %s", hash, name)
	}
}

func TestNonceBytes(t *testing.T) {
	nonce, err := nonceBytes(&NonceOptions{Value: "aabb"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(nonce, []byte{0xaa, 0xbb}) {
		t.Fatalf("unexpected nonce: %x", nonce)
	}

	nonce, err = nonceBytes(&NonceOptions{Length: 4})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nonce) != 4 {
		t.Fatalf("expected 4 byte nonce, got %d", len(nonce))
	}

	if _, err := nonceBytes(&NonceOptions{Length: 129}); err == nil {
		t.Fatal("expected error for oversized nonce")
	}
}

func TestAddNonceExtension(t *testing.T) {
	requestList := der.EncodeSequence(der.EncodeSequence([]byte{}))
	tbsRequest := der.EncodeSequence(requestList)
	ocspRequest := der.EncodeSequence(tbsRequest)
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	result, err := addNonceToOCSPRequest(ocspRequest, nonce)
	if err != nil {
		t.Errorf("Failed to add nonce extension: %v", err)
	}
	if len(result) < len(ocspRequest)+10 {
		t.Errorf("Result too short, nonce extension may not be added properly")
	}
	if result[0] != 0x30 {
		t.Errorf("Expected SEQUENCE tag (0x30), got 0x%02x", result[0])
	}

	_, contentStart, err := der.ReadDERLength(result, 1)
	if err != nil {
		t.Fatalf("Failed to parse result length: %v", err)
	}
	if contentStart >= len(result) {
		t.Errorf("Invalid result structure")
	}
}
