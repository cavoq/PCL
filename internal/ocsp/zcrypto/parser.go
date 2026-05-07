package zcrypto

import (
	"encoding/hex"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

// NonceState represents the parsed nonce extension.
type NonceState struct {
	Present  bool
	Value    []byte
	Length   int
	HexValue string
}

// Nonce OID: id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2)
const nonceOID = "1.3.6.1.5.5.7.48.1.2"

// ParseNonceFromRaw extracts the nonce from OCSP responseExtensions.
// The nonce is in responseExtensions (inside TBSResponseData), NOT in singleExtensions.
// Returns NonceState with Present=false if nonce not found.
func ParseNonceFromRaw(rawOCSP []byte) NonceState {
	result := NonceState{Present: false}

	input := cryptobyte.String(rawOCSP)

	// Read OCSPResponse SEQUENCE
	var ocspResp cryptobyte.String
	if !input.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// Read ResponseStatus (ENUMERATED)
	var status cryptobyte.String
	if !ocspResp.ReadASN1(&status, cryptobyte_asn1.ENUM) {
		return result
	}

	// Read ResponseBytes (context-specific [0] EXPLICIT)
	var responseBytesOuter cryptobyte.String
	if !ocspResp.ReadASN1(&responseBytesOuter, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return result
	}

	// Inside the [0] wrapper, read ResponseBytes SEQUENCE
	var responseBytes cryptobyte.String
	if !responseBytesOuter.ReadASN1(&responseBytes, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// Skip responseType OID
	var responseType cryptobyte.String
	if !responseBytes.ReadASN1(&responseType, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return result
	}

	// Read response OCTET STRING (contains BasicOCSPResponse)
	var responseOctet cryptobyte.String
	if !responseBytes.ReadASN1(&responseOctet, cryptobyte_asn1.OCTET_STRING) {
		return result
	}

	// Parse BasicOCSPResponse from OCTET STRING
	var basicResp cryptobyte.String
	if !responseOctet.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// Parse TBSResponseData SEQUENCE
	var tbsResp cryptobyte.String
	if !basicResp.ReadASN1(&tbsResp, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// Now we need to parse TBSResponseData to find responseExtensions [1]
	// TBSResponseData structure:
	//   version [0] EXPLICIT OPTIONAL (INTEGER)
	//   responderID CHOICE
	//   producedAt GeneralizedTime
	//   responses SEQUENCE OF SingleResponse
	//   responseExtensions [1] EXPLICIT OPTIONAL

	// Skip version [0] if present
	tbsResp.SkipOptionalASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed())

	// Skip responderID (either byName [1] or byKey [2])
	var responderIDTag cryptobyte_asn1.Tag
	var responderID cryptobyte.String
	if !tbsResp.ReadAnyASN1(&responderID, &responderIDTag) {
		return result
	}

	// Skip producedAt (GeneralizedTime)
	var producedAt cryptobyte.String
	if !tbsResp.ReadASN1(&producedAt, cryptobyte_asn1.GeneralizedTime) {
		return result
	}

	// Skip responses SEQUENCE OF SingleResponse
	var responses cryptobyte.String
	if !tbsResp.ReadASN1(&responses, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// Now look for responseExtensions [1] EXPLICIT
	var extensionsOuter cryptobyte.String
	if !tbsResp.ReadASN1(&extensionsOuter, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) {
		// No responseExtensions present
		return result
	}

	// Inside [1] wrapper, read extensions SEQUENCE
	var extensions cryptobyte.String
	if !extensionsOuter.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	// Iterate through extensions looking for nonce OID
	for !extensions.Empty() {
		var ext cryptobyte.String
		if !extensions.ReadASN1(&ext, cryptobyte_asn1.SEQUENCE) {
			break
		}

		// Read OID
		var oid cryptobyte.String
		if !ext.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			break
		}

		oidStr := oidString(oid)
		if oidStr != nonceOID {
			continue
		}

		// Found nonce extension
		// Skip critical flag (optional BOOLEAN)
		ext.SkipOptionalASN1(cryptobyte_asn1.BOOLEAN)

		// Read extnValue (OCTET STRING containing the nonce)
		var extnValue cryptobyte.String
		if !ext.ReadASN1(&extnValue, cryptobyte_asn1.OCTET_STRING) {
			break
		}

		// The nonce itself is an OCTET STRING inside extnValue
		var nonceValue cryptobyte.String
		if extnValue.ReadASN1(&nonceValue, cryptobyte_asn1.OCTET_STRING) {
			result.Present = true
			result.Value = []byte(nonceValue)
			result.Length = len(result.Value)
			result.HexValue = hex.EncodeToString(result.Value)
		} else {
			// Fallback: treat extnValue as the nonce directly
			result.Present = true
			result.Value = []byte(extnValue)
			result.Length = len(result.Value)
			result.HexValue = hex.EncodeToString(result.Value)
		}

		return result
	}

	return result
}

// oidString converts cryptobyte.String OID to dotted string format.
func oidString(oid cryptobyte.String) string {
	var components []int

	// First two components are encoded specially: first*40 + second
	var firstByte uint8
	if !oid.ReadUint8(&firstByte) {
		return ""
	}
	components = append(components, int(firstByte)/40)
	components = append(components, int(firstByte)%40)

	// Remaining components use base128 encoding
	for !oid.Empty() {
		var val int
		if !readBase128Int(&oid, &val) {
			break
		}
		components = append(components, val)
	}

	// Build dotted string
	result := ""
	for i, comp := range components {
		if i > 0 {
			result += "."
		}
		result += intToString(comp)
	}
	return result
}

// readBase128Int reads a base128-encoded integer from cryptobyte.String.
func readBase128Int(s *cryptobyte.String, out *int) bool {
	var val int
	var b uint8
	for {
		if !s.ReadUint8(&b) {
			return false
		}
		val <<= 7
		val |= int(b & 0x7f)
		if b&0x80 == 0 {
			break
		}
	}
	*out = val
	return true
}

// intToString converts int to string without importing strconv.
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ParseOCSPSignatureAlgorithmParams parses the signatureAlgorithm
// from an OCSP response and returns the parameters state.
// OCSP structure: OCSPResponse -> responseBytes -> BasicOCSPResponse -> signatureAlgorithm
func ParseOCSPSignatureAlgorithmParams(rawOCSP []byte) asn1.ParamsState {
	input := cryptobyte.String(rawOCSP)

	// Read OCSPResponse SEQUENCE
	var ocspResp cryptobyte.String
	if !input.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read ResponseStatus (ENUMERATED - Tag(10))
	var status cryptobyte.String
	if !ocspResp.ReadASN1(&status, cryptobyte_asn1.ENUM) {
		return asn1.ParamsState{}
	}

	// Read ResponseBytes (context-specific [0] EXPLICIT)
	// The [0] tag is context-specific and constructed (EXPLICIT means wrapped in another SEQUENCE)
	var responseBytesOuter cryptobyte.String
	if !ocspResp.ReadASN1(&responseBytesOuter, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return asn1.ParamsState{}
	}

	// Inside the [0] wrapper, we have ResponseBytes SEQUENCE
	var responseBytes cryptobyte.String
	if !responseBytesOuter.ReadASN1(&responseBytes, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip responseType OID
	var responseType cryptobyte.String
	if !responseBytes.ReadASN1(&responseType, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return asn1.ParamsState{}
	}

	// Read response OCTET STRING (contains BasicOCSPResponse)
	var responseOctet cryptobyte.String
	if !responseBytes.ReadASN1(&responseOctet, cryptobyte_asn1.OCTET_STRING) {
		return asn1.ParamsState{}
	}

	// Parse BasicOCSPResponse from OCTET STRING
	var basicResp cryptobyte.String
	if !responseOctet.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip TBSResponseData SEQUENCE
	var tbsResp cryptobyte.String
	if !basicResp.ReadASN1(&tbsResp, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read signatureAlgorithm (AlgorithmIdentifier after TBSResponseData)
	var sigAlgo cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !basicResp.ReadAnyASN1Element(&sigAlgo, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgo)
}
