package asn1

import (
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

// oidString converts a cryptobyte OID to standard string format (e.g., "1.2.840.113549.1.1.11").
func oidString(oid cryptobyte.String) string {
	var components []int

	var first byte
	if !oid.ReadUint8(&first) {
		return ""
	}
	components = append(components, int(first/40), int(first%40))

	for !oid.Empty() {
		var val int
		if !readOIDComponent(&oid, &val) {
			break
		}
		components = append(components, val)
	}

	result := ""
	for i, c := range components {
		if i > 0 {
			result += "."
		}
		result += strconv.Itoa(c)
	}
	return result
}

func readOIDComponent(oid *cryptobyte.String, val *int) bool {
	var v int
	for {
		var b byte
		if !oid.ReadUint8(&b) {
			return false
		}
		v = (v << 7) | int(b&0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	*val = v
	return true
}
