package asn1

import (
	stdasn1 "encoding/asn1"
	"fmt"
)

// EncodeOctetString encodes content as a DER OCTET STRING.
func EncodeOctetString(content []byte) []byte {
	return encodeTagged(0x04, content)
}

// EncodeSequence encodes content as a DER SEQUENCE.
func EncodeSequence(content []byte) []byte {
	return encodeTagged(0x30, content)
}

// EncodeContextSpecificConstructed encodes content as a DER context-specific constructed tag.
func EncodeContextSpecificConstructed(tag int, content []byte) []byte {
	return encodeTagged(byte(0xA0|tag), content)
}

// EncodeObjectIdentifier encodes oid as a DER OBJECT IDENTIFIER.
func EncodeObjectIdentifier(oid stdasn1.ObjectIdentifier) ([]byte, error) {
	encoded, err := stdasn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("failed to encode object identifier: %w", err)
	}
	return encoded, nil
}

// ReadDERLength reads a DER length at pos and returns the length and content start offset.
func ReadDERLength(data []byte, pos int) (int, int, error) {
	if pos < 0 || pos >= len(data) {
		return 0, 0, fmt.Errorf("invalid DER length offset")
	}
	if data[pos] < 128 {
		return int(data[pos]), pos + 1, nil
	}

	lenBytes := int(data[pos] & 0x7F)
	if lenBytes == 0 {
		return 0, 0, fmt.Errorf("indefinite DER length is not allowed")
	}
	if pos+lenBytes >= len(data) {
		return 0, 0, fmt.Errorf("invalid DER length")
	}

	length := 0
	for i := 0; i < lenBytes; i++ {
		length = (length << 8) | int(data[pos+1+i])
	}
	return length, pos + 1 + lenBytes, nil
}

func encodeTagged(tag byte, content []byte) []byte {
	result := []byte{tag}
	result = append(result, encodeDERLength(len(content))...)
	result = append(result, content...)
	return result
}

func encodeDERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}

	var result []byte
	for length > 0 {
		result = append([]byte{byte(length & 0xFF)}, result...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(result))}, result...)
}
