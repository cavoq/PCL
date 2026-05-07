package zcrypto

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

// ParseTBSCRLSignatureParams parses the signature AlgorithmIdentifier
// from TBSCertList and returns the parameters state.
// TBSCertList structure: version (optional) -> signature -> issuer -> thisUpdate...
func ParseTBSCRLSignatureParams(rawTBSRevocationList []byte) asn1.ParamsState {
	input := cryptobyte.String(rawTBSRevocationList)

	var tbsCRL cryptobyte.String
	if !input.ReadASN1(&tbsCRL, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip version (optional INTEGER)
	tbsCRL.SkipOptionalASN1(cryptobyte_asn1.INTEGER)

	// Read signature AlgorithmIdentifier (immediately after version)
	var sigAlgoID cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !tbsCRL.ReadAnyASN1Element(&sigAlgoID, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgoID)
}

// ParseCRLSignatureAlgorithmParams parses the outer signatureAlgorithm
// from a CRL and returns the parameters state.
func ParseCRLSignatureAlgorithmParams(rawCRL []byte) asn1.ParamsState {
	input := cryptobyte.String(rawCRL)

	var crl cryptobyte.String
	if !input.ReadASN1(&crl, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Skip TBSCertList
	var tbs cryptobyte.String
	if !crl.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{}
	}

	// Read signatureAlgorithm
	var sigAlgo cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !crl.ReadAnyASN1Element(&sigAlgo, &tag) {
		return asn1.ParamsState{}
	}

	return asn1.ParseAlgorithmIDParams(sigAlgo)
}