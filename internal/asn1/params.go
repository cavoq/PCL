package asn1

// ParamsState represents the state of an AlgorithmIdentifier parameters field.
type ParamsState struct {
	IsNull     bool   // parameters is ASN.1 NULL
	IsAbsent   bool   // parameters field is absent
	OID        string // algorithm OID
	NamedCurve string // namedCurve OID for ECDSA (from parameters field)
	RawDER     []byte // raw DER bytes of the entire AlgorithmIdentifier SEQUENCE

	// RSASSA-PSS parameters (OID 1.2.840.113549.1.1.10)
	PSS *PSSParams

	// RSAES-OAEP parameters (OID 1.2.840.113549.1.1.7)
	OAEP *OAEPParams
}

// PSSParams represents RSASSA-PSS-params structure.
type PSSParams struct {
	HashAlgorithm       AlgorithmIdentifier // [0] DEFAULT sha1
	MaskGenAlgorithm    AlgorithmIdentifier // [1] DEFAULT mgf1SHA1
	SaltLength          int                 // [2] DEFAULT 20
	TrailerField        int                 // [3] DEFAULT 1
	HashAlgorithmSet    bool                // whether hashAlgorithm was explicitly set
	MaskGenAlgorithmSet bool                // whether maskGenAlgorithm was explicitly set
	SaltLengthSet       bool                // whether saltLength was explicitly set
	TrailerFieldSet     bool                // whether trailerField was explicitly set
}

// OAEPParams represents RSAES-OAEP-params structure.
type OAEPParams struct {
	HashAlgorithm       AlgorithmIdentifier // [0] DEFAULT sha1
	MaskGenAlgorithm    AlgorithmIdentifier // [1] DEFAULT mgf1SHA1
	PSourceAlgorithm    AlgorithmIdentifier // [2] DEFAULT pSpecifiedEmpty
	HashAlgorithmSet    bool                // whether hashAlgorithm was explicitly set
	MaskGenAlgorithmSet bool                // whether maskGenAlgorithm was explicitly set
	PSourceAlgorithmSet bool                // whether pSourceAlgorithm was explicitly set
}

// AlgorithmIdentifier represents an AlgorithmIdentifier structure.
type AlgorithmIdentifier struct {
	OID    string
	Params ParamsState // nested params for MGF1, etc.
}
