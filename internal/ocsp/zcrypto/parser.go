package zcrypto

import (
	stdasn1 "encoding/asn1"
	"encoding/hex"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
	oidpkg "github.com/cavoq/PCL/internal/oid"
)

// NonceState represents the parsed nonce extension.
type NonceState struct {
	Present  bool
	Value    []byte
	Length   int
	HexValue string
}

// CertID contains the issuer binding carried by the first SingleResponse in
// a BasicOCSPResponse. The semantic comparison with a candidate issuer belongs
// to the parent OCSP domain package.
type CertID struct {
	IssuerNameHash []byte
	IssuerKeyHash  []byte
}

// ParseNonceFromRaw extracts the nonce from OCSP responseExtensions.
// The nonce is in responseExtensions (inside TBSResponseData), NOT in singleExtensions.
// Returns NonceState with Present=false if nonce not found.
func ParseNonceFromRaw(rawOCSP []byte) NonceState {
	result := NonceState{Present: false}

	basicDER, ok := readBasicOCSPResponse(rawOCSP)
	if !ok {
		return result
	}

	var basicResp cryptobyte.String
	if !basicDER.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
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
		var oid stdasn1.ObjectIdentifier
		if !ext.ReadASN1ObjectIdentifier(&oid) {
			break
		}

		if oid.String() != oidpkg.OCSPNonce {
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

// ParseOCSPSignatureAlgorithmParams parses the signatureAlgorithm
// from an OCSP response and returns the parameters state.
// OCSP structure: OCSPResponse -> responseBytes -> BasicOCSPResponse -> signatureAlgorithm
func ParseOCSPSignatureAlgorithmParams(rawOCSP []byte) asn1.ParamsState {
	basicDER, ok := readBasicOCSPResponse(rawOCSP)
	if !ok {
		return asn1.ParamsState{}
	}
	return asn1.ParseSignedObjectAlgorithmParams(basicDER)
}

// ParseCertID extracts the issuer name and key hashes from the first
// SingleResponse in an OCSP response. golang.org/x/crypto/ocsp exposes the
// selected hash algorithm but not these two encoded hash values.
func ParseCertID(rawOCSP []byte) (CertID, bool) {
	basicDER, ok := readBasicOCSPResponse(rawOCSP)
	if !ok {
		return CertID{}, false
	}

	var basicResponse cryptobyte.String
	if !basicDER.ReadASN1(&basicResponse, cryptobyte_asn1.SEQUENCE) || !basicDER.Empty() {
		return CertID{}, false
	}

	var responseData cryptobyte.String
	if !basicResponse.ReadASN1(&responseData, cryptobyte_asn1.SEQUENCE) {
		return CertID{}, false
	}
	if !responseData.SkipOptionalASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return CertID{}, false
	}

	var responderID cryptobyte.String
	var responderIDTag cryptobyte_asn1.Tag
	if !responseData.ReadAnyASN1(&responderID, &responderIDTag) {
		return CertID{}, false
	}
	if !responseData.SkipASN1(cryptobyte_asn1.GeneralizedTime) {
		return CertID{}, false
	}

	var responses cryptobyte.String
	if !responseData.ReadASN1(&responses, cryptobyte_asn1.SEQUENCE) {
		return CertID{}, false
	}

	var singleResponse cryptobyte.String
	if !responses.ReadASN1(&singleResponse, cryptobyte_asn1.SEQUENCE) {
		return CertID{}, false
	}

	var certID cryptobyte.String
	if !singleResponse.ReadASN1(&certID, cryptobyte_asn1.SEQUENCE) {
		return CertID{}, false
	}

	var hashAlgorithm cryptobyte.String
	if !certID.ReadASN1(&hashAlgorithm, cryptobyte_asn1.SEQUENCE) {
		return CertID{}, false
	}

	var issuerNameHash cryptobyte.String
	if !certID.ReadASN1(&issuerNameHash, cryptobyte_asn1.OCTET_STRING) {
		return CertID{}, false
	}
	var issuerKeyHash cryptobyte.String
	if !certID.ReadASN1(&issuerKeyHash, cryptobyte_asn1.OCTET_STRING) {
		return CertID{}, false
	}
	if !certID.SkipASN1(cryptobyte_asn1.INTEGER) || !certID.Empty() {
		return CertID{}, false
	}

	return CertID{
		IssuerNameHash: append([]byte(nil), issuerNameHash...),
		IssuerKeyHash:  append([]byte(nil), issuerKeyHash...),
	}, true
}

// readBasicOCSPResponse returns the DER-encoded BasicOCSPResponse carried in
// an OCSPResponse. The OCSP envelope traversal is shared by nonce and
// signature-algorithm parsing, while interpretation remains with each caller.
func readBasicOCSPResponse(rawOCSP []byte) (cryptobyte.String, bool) {
	input := cryptobyte.String(rawOCSP)

	var ocspResp cryptobyte.String
	if !input.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, false
	}

	var status cryptobyte.String
	if !ocspResp.ReadASN1(&status, cryptobyte_asn1.ENUM) {
		return nil, false
	}

	var responseBytesOuter cryptobyte.String
	if !ocspResp.ReadASN1(&responseBytesOuter, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, false
	}

	var responseBytes cryptobyte.String
	if !responseBytesOuter.ReadASN1(&responseBytes, cryptobyte_asn1.SEQUENCE) || !responseBytesOuter.Empty() {
		return nil, false
	}

	var responseType stdasn1.ObjectIdentifier
	if !responseBytes.ReadASN1ObjectIdentifier(&responseType) || responseType.String() != oidpkg.OCSPBasicResponse {
		return nil, false
	}

	var basicDER cryptobyte.String
	if !responseBytes.ReadASN1(&basicDER, cryptobyte_asn1.OCTET_STRING) || !responseBytes.Empty() {
		return nil, false
	}
	return basicDER, true
}
