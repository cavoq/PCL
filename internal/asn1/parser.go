package asn1

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	oidSHA1       = "1.3.14.3.2.26"
	oidMGF1       = "1.2.840.113549.1.1.8"
	oidRSAPSS     = "1.2.840.113549.1.1.10"
	oidRSAOAEP    = "1.2.840.113549.1.1.7"
	oidPSpecified = "1.2.840.113549.1.1.9"
)

// ParseAlgorithmIDParams parses an AlgorithmIdentifier from DER bytes
// and returns the parameters state and OID.
func ParseAlgorithmIDParams(derBytes []byte) ParamsState {
	result := ParamsState{}
	// Store raw DER bytes for byte-for-byte encoding validation (Mozilla requirements)
	result.RawDER = derBytes

	input := cryptobyte.String(derBytes)

	var algoID cryptobyte.String
	if !input.ReadASN1(&algoID, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	var oid cryptobyte.String
	if !algoID.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return result
	}

	// Convert OID to string representation
	result.OID = oidString(oid)

	if algoID.Empty() {
		result.IsAbsent = true
		return result
	}

	var params cryptobyte.String
	var paramsTag cryptobyte_asn1.Tag
	if !algoID.ReadAnyASN1Element(&params, &paramsTag) {
		return result
	}

	if paramsTag == cryptobyte_asn1.NULL {
		result.IsNull = true
		return result
	}

	// For ECDSA (id-ecPublicKey), parameters is a namedCurve OID
	// ECDSA OIDs: 1.2.840.10045.2.1 (id-ecPublicKey), 1.3.132.1.12 (id-ecDH), 1.3.132.1.13 (id-ecMQV)
	if paramsTag == cryptobyte_asn1.OBJECT_IDENTIFIER {
		var namedCurve cryptobyte.String
		if params.ReadASN1(&namedCurve, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			result.NamedCurve = oidString(namedCurve)
		}
		return result
	}

	// Parse RSASSA-PSS parameters (OID 1.2.840.113549.1.1.10)
	if result.OID == oidRSAPSS {
		result.PSS = parsePSSParams(params)
		return result
	}

	// Parse RSAES-OAEP parameters (OID 1.2.840.113549.1.1.7)
	if result.OID == oidRSAOAEP {
		result.OAEP = parseOAEPParams(params)
		return result
	}

	return result
}

// parsePSSParams parses RSASSA-PSS-params from a SEQUENCE.
func parsePSSParams(params cryptobyte.String) *PSSParams {
	result := &PSSParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: oidSHA1},
		MaskGenAlgorithm: AlgorithmIdentifier{OID: oidMGF1, Params: ParamsState{OID: oidSHA1}},
		SaltLength:       20,
		TrailerField:     1,
	}

	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	if algo, ok := readExplicitAlgorithmIdentifier(&seq, 0); ok {
		result.HashAlgorithmSet = true
		result.HashAlgorithm = algo
	}

	if algo, ok := readExplicitAlgorithmIdentifier(&seq, 1); ok {
		result.MaskGenAlgorithmSet = true
		result.MaskGenAlgorithm = algo
	}

	if value, ok := readExplicitInteger(&seq, 2); ok {
		result.SaltLengthSet = true
		result.SaltLength = value
	}

	if value, ok := readExplicitInteger(&seq, 3); ok {
		result.TrailerFieldSet = true
		result.TrailerField = value
	}

	return result
}

// parseOAEPParams parses RSAES-OAEP-params from a SEQUENCE.
func parseOAEPParams(params cryptobyte.String) *OAEPParams {
	result := &OAEPParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: oidSHA1},
		MaskGenAlgorithm: AlgorithmIdentifier{OID: oidMGF1, Params: ParamsState{OID: oidSHA1}},
		PSourceAlgorithm: AlgorithmIdentifier{OID: oidPSpecified},
	}

	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	if algo, ok := readExplicitAlgorithmIdentifier(&seq, 0); ok {
		result.HashAlgorithmSet = true
		result.HashAlgorithm = algo
	}

	if algo, ok := readExplicitAlgorithmIdentifier(&seq, 1); ok {
		result.MaskGenAlgorithmSet = true
		result.MaskGenAlgorithm = algo
	}

	if algo, ok := readExplicitAlgorithmIdentifier(&seq, 2); ok {
		result.PSourceAlgorithmSet = true
		result.PSourceAlgorithm = algo
	}

	return result
}

func readExplicitAlgorithmIdentifier(seq *cryptobyte.String, tag uint) (AlgorithmIdentifier, bool) {
	var value cryptobyte.String
	present, ok := readExplicit(seq, tag, &value)
	if !present {
		return AlgorithmIdentifier{}, false
	}
	if !ok {
		return AlgorithmIdentifier{}, true
	}
	return parseNestedAlgorithmIdentifier(value), true
}

func readExplicitInteger(seq *cryptobyte.String, tag uint) (int, bool) {
	var value cryptobyte.String
	present, ok := readExplicit(seq, tag, &value)
	if !present {
		return 0, false
	}
	if !ok {
		return 0, true
	}
	var result int
	if !value.ReadASN1Integer(&result) {
		return 0, true
	}
	return result, true
}

func readExplicit(seq *cryptobyte.String, tag uint, out *cryptobyte.String) (present bool, ok bool) {
	if seq.Empty() {
		return false, false
	}
	asn1Tag := cryptobyte_asn1.Tag(tag).Constructed().ContextSpecific()
	if !seq.PeekASN1Tag(asn1Tag) {
		return false, false
	}
	return true, seq.ReadASN1(out, asn1Tag)
}

// parseNestedAlgorithmIdentifier parses an AlgorithmIdentifier structure.
func parseNestedAlgorithmIdentifier(input cryptobyte.String) AlgorithmIdentifier {
	result := AlgorithmIdentifier{}

	var algoID cryptobyte.String
	if !input.ReadASN1(&algoID, cryptobyte_asn1.SEQUENCE) {
		return result
	}

	var oid cryptobyte.String
	if !algoID.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return result
	}

	result.OID = oidString(oid)

	if algoID.Empty() {
		result.Params.IsAbsent = true
		return result
	}

	var params cryptobyte.String
	var paramsTag cryptobyte_asn1.Tag
	if !algoID.ReadAnyASN1Element(&params, &paramsTag) {
		return result
	}

	if paramsTag == cryptobyte_asn1.NULL {
		result.Params.IsNull = true
		result.Params.OID = result.OID
		return result
	}

	// For MGF1, the parameter is another AlgorithmIdentifier (hash algorithm)
	if result.OID == oidMGF1 {
		result.Params = ParseAlgorithmIDParams(params)
	}

	return result
}
