package asn1

import (
	stdasn1 "encoding/asn1"
	"fmt"

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

// ParseAlgorithmIDParams parses an AlgorithmIdentifier from DER bytes. It is
// kept as a compatibility wrapper for callers that consume ParamsState only;
// malformed input is reported through ParamsState.Malformed.
func ParseAlgorithmIDParams(derBytes []byte) ParamsState {
	if len(derBytes) == 0 {
		return ParamsState{}
	}
	result, err := ParseAlgorithmIDParamsStrict(derBytes)
	if err != nil {
		result.Malformed = true
	}
	return result
}

// ParseAlgorithmIDParamsStrict parses exactly one DER AlgorithmIdentifier.
// It distinguishes an absent parameters field from malformed DER and retains
// the complete identifier and parameter encodings for byte-level rules.
func ParseAlgorithmIDParamsStrict(derBytes []byte) (ParamsState, error) {
	result := ParamsState{RawDER: append([]byte(nil), derBytes...)}
	input := cryptobyte.String(derBytes)

	var algoID cryptobyte.String
	if !input.ReadASN1(&algoID, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return result, fmt.Errorf("invalid AlgorithmIdentifier sequence")
	}

	var objectID stdasn1.ObjectIdentifier
	if !algoID.ReadASN1ObjectIdentifier(&objectID) {
		return result, fmt.Errorf("invalid AlgorithmIdentifier OID")
	}
	result.OID = objectID.String()

	if algoID.Empty() {
		result.IsAbsent = true
		return result, nil
	}

	var params cryptobyte.String
	var paramsTag cryptobyte_asn1.Tag
	if !algoID.ReadAnyASN1Element(&params, &paramsTag) || !algoID.Empty() {
		return result, fmt.Errorf("AlgorithmIdentifier must contain exactly one parameters element")
	}
	result.RawParams = append([]byte(nil), params...)

	if result.OID == oidRSAPSS || result.OID == oidRSAOAEP {
		if paramsTag != cryptobyte_asn1.SEQUENCE {
			return result, fmt.Errorf("algorithm %s parameters must be a SEQUENCE", result.OID)
		}
		var err error
		if result.OID == oidRSAPSS {
			result.PSS, err = parsePSSParamsStrict(params)
		} else {
			result.OAEP, err = parseOAEPParamsStrict(params)
		}
		if err != nil {
			return result, err
		}
		return result, nil
	}

	switch paramsTag {
	case cryptobyte_asn1.NULL:
		value := params
		var nullValue cryptobyte.String
		if !value.ReadASN1(&nullValue, cryptobyte_asn1.NULL) || !value.Empty() || !nullValue.Empty() {
			return result, fmt.Errorf("invalid NULL algorithm parameters")
		}
		result.IsNull = true
	case cryptobyte_asn1.OBJECT_IDENTIFIER:
		value := params
		var namedCurve stdasn1.ObjectIdentifier
		if !value.ReadASN1ObjectIdentifier(&namedCurve) || !value.Empty() {
			return result, fmt.Errorf("invalid object identifier algorithm parameters")
		}
		result.NamedCurve = namedCurve.String()
	}

	return result, nil
}

// ParseSignedObjectAlgorithmParams extracts the outer AlgorithmIdentifier from
// a DER signed object whose first fields are a TBS SEQUENCE followed by an
// AlgorithmIdentifier. Certificates, CRLs, and BasicOCSPResponse all use this
// envelope shape.
func ParseSignedObjectAlgorithmParams(derBytes []byte) ParamsState {
	if len(derBytes) == 0 {
		return ParamsState{}
	}
	result, err := ParseSignedObjectAlgorithmParamsStrict(derBytes)
	if err != nil {
		result.Malformed = true
	}
	return result
}

// ParseSignedObjectAlgorithmParamsStrict extracts and strictly parses the
// outer AlgorithmIdentifier from a signed-object envelope.
func ParseSignedObjectAlgorithmParamsStrict(derBytes []byte) (ParamsState, error) {
	input := cryptobyte.String(derBytes)
	var signedObject cryptobyte.String
	if !input.ReadASN1(&signedObject, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return ParamsState{}, fmt.Errorf("invalid signed-object sequence")
	}
	if !signedObject.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return ParamsState{}, fmt.Errorf("invalid signed-object payload")
	}

	var algorithmDER cryptobyte.String
	if !signedObject.ReadASN1Element(&algorithmDER, cryptobyte_asn1.SEQUENCE) {
		return ParamsState{}, fmt.Errorf("invalid signed-object AlgorithmIdentifier")
	}
	return ParseAlgorithmIDParamsStrict(algorithmDER)
}

// parsePSSParams parses RSASSA-PSS-params from a SEQUENCE.
func parsePSSParamsStrict(params cryptobyte.String) (*PSSParams, error) {
	result := &PSSParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: oidSHA1},
		MaskGenAlgorithm: AlgorithmIdentifier{OID: oidMGF1, Params: ParamsState{OID: oidSHA1}},
		SaltLength:       20,
		TrailerField:     1,
	}

	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !params.Empty() {
		return result, fmt.Errorf("invalid RSASSA-PSS parameters")
	}

	if algo, present, err := readExplicitAlgorithmIdentifier(&seq, 0); err != nil {
		return result, fmt.Errorf("invalid RSASSA-PSS hashAlgorithm: %w", err)
	} else if present {
		result.HashAlgorithmSet = true
		result.HashAlgorithm = algo
	}

	if algo, present, err := readExplicitAlgorithmIdentifier(&seq, 1); err != nil {
		return result, fmt.Errorf("invalid RSASSA-PSS maskGenAlgorithm: %w", err)
	} else if present {
		result.MaskGenAlgorithmSet = true
		result.MaskGenAlgorithm = algo
	}

	if value, present, err := readExplicitInteger(&seq, 2); err != nil {
		return result, fmt.Errorf("invalid RSASSA-PSS saltLength: %w", err)
	} else if present {
		result.SaltLengthSet = true
		result.SaltLength = value
	}

	if value, present, err := readExplicitInteger(&seq, 3); err != nil {
		return result, fmt.Errorf("invalid RSASSA-PSS trailerField: %w", err)
	} else if present {
		result.TrailerFieldSet = true
		result.TrailerField = value
	}

	if !seq.Empty() {
		return result, fmt.Errorf("unexpected RSASSA-PSS parameter field")
	}
	return result, nil
}

// parseOAEPParams parses RSAES-OAEP-params from a SEQUENCE.
func parseOAEPParamsStrict(params cryptobyte.String) (*OAEPParams, error) {
	result := &OAEPParams{
		HashAlgorithm:    AlgorithmIdentifier{OID: oidSHA1},
		MaskGenAlgorithm: AlgorithmIdentifier{OID: oidMGF1, Params: ParamsState{OID: oidSHA1}},
		PSourceAlgorithm: AlgorithmIdentifier{OID: oidPSpecified},
	}

	var seq cryptobyte.String
	if !params.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !params.Empty() {
		return result, fmt.Errorf("invalid RSAES-OAEP parameters")
	}

	if algo, present, err := readExplicitAlgorithmIdentifier(&seq, 0); err != nil {
		return result, fmt.Errorf("invalid RSAES-OAEP hashAlgorithm: %w", err)
	} else if present {
		result.HashAlgorithmSet = true
		result.HashAlgorithm = algo
	}

	if algo, present, err := readExplicitAlgorithmIdentifier(&seq, 1); err != nil {
		return result, fmt.Errorf("invalid RSAES-OAEP maskGenAlgorithm: %w", err)
	} else if present {
		result.MaskGenAlgorithmSet = true
		result.MaskGenAlgorithm = algo
	}

	if algo, present, err := readExplicitAlgorithmIdentifier(&seq, 2); err != nil {
		return result, fmt.Errorf("invalid RSAES-OAEP pSourceAlgorithm: %w", err)
	} else if present {
		result.PSourceAlgorithmSet = true
		result.PSourceAlgorithm = algo
	}

	if !seq.Empty() {
		return result, fmt.Errorf("unexpected RSAES-OAEP parameter field")
	}
	return result, nil
}

func readExplicitAlgorithmIdentifier(seq *cryptobyte.String, tag uint) (AlgorithmIdentifier, bool, error) {
	var value cryptobyte.String
	present, ok := readExplicit(seq, tag, &value)
	if !present {
		return AlgorithmIdentifier{}, false, nil
	}
	if !ok {
		return AlgorithmIdentifier{}, true, fmt.Errorf("invalid explicit wrapper")
	}
	algorithm, err := parseNestedAlgorithmIdentifier(value)
	return algorithm, true, err
}

func readExplicitInteger(seq *cryptobyte.String, tag uint) (int, bool, error) {
	var value cryptobyte.String
	present, ok := readExplicit(seq, tag, &value)
	if !present {
		return 0, false, nil
	}
	if !ok {
		return 0, true, fmt.Errorf("invalid explicit wrapper")
	}
	var result int
	if !value.ReadASN1Integer(&result) || !value.Empty() {
		return 0, true, fmt.Errorf("invalid integer")
	}
	return result, true, nil
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
func parseNestedAlgorithmIdentifier(input cryptobyte.String) (AlgorithmIdentifier, error) {
	result := AlgorithmIdentifier{}

	params, err := ParseAlgorithmIDParamsStrict(input)
	if err != nil {
		return result, err
	}
	result.OID = params.OID
	result.Params = params
	if result.OID == oidMGF1 {
		if len(params.RawParams) == 0 {
			return AlgorithmIdentifier{}, fmt.Errorf("MGF1 parameters are absent")
		}
		nested, err := ParseAlgorithmIDParamsStrict(params.RawParams)
		if err != nil {
			return AlgorithmIdentifier{}, fmt.Errorf("invalid MGF1 hash algorithm: %w", err)
		}
		result.Params = nested
	}
	return result, nil
}
