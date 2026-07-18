// Package oid provides X.509 OID constants and lookups.
package oid

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// ValidDotted reports whether value is a canonical dotted-decimal object
// identifier. It rejects leading zeroes and invalid first/second arcs.
func ValidDotted(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}

	arcs := make([]uint64, len(parts))
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		arc, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return false
		}
		arcs[index] = arc
	}
	if arcs[0] > 2 {
		return false
	}
	return arcs[0] == 2 || arcs[1] <= 39
}

// Parse converts a canonical dotted-decimal identifier to the standard
// library's ASN.1 representation. Callers should keep identifiers as strings
// until they reach an ASN.1 encoding boundary.
func Parse(value string) (stdasn1.ObjectIdentifier, error) {
	if !ValidDotted(value) {
		return nil, fmt.Errorf("invalid object identifier %q", value)
	}

	parts := strings.Split(value, ".")
	result := make(stdasn1.ObjectIdentifier, len(parts))
	for index, part := range parts {
		arc, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid object identifier %q: %w", value, err)
		}
		result[index] = arc
	}
	return result, nil
}

// NormalizeOID converts a friendly name to its OID string.
// If the input is already an OID or a built-in cert type, it is returned unchanged.
func NormalizeOID(nameOrOID string) string {
	if value, ok := ExtKeyUsageOID(nameOrOID); ok {
		return value
	}
	if value, ok := ExtensionOID(nameOrOID); ok {
		return value
	}
	return nameOrOID
}
