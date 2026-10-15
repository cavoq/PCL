package crlnode

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/x509asn1"
)

// parseTBSCRLSignatureParams parses the signature AlgorithmIdentifier
// from TBSCertList and returns the parameters state.
// TBSCertList structure: version (optional) -> signature -> issuer -> thisUpdate...
func parseTBSCRLSignatureParams(rawTBSRevocationList []byte) x509asn1.ParamsState {
	input := cryptobyte.String(rawTBSRevocationList)

	var tbsCRL cryptobyte.String
	if !input.ReadASN1(&tbsCRL, cryptobyte_asn1.SEQUENCE) {
		return x509asn1.ParamsState{}
	}

	// Skip version (optional INTEGER)
	tbsCRL.SkipOptionalASN1(cryptobyte_asn1.INTEGER)

	// Read signature AlgorithmIdentifier (immediately after version)
	var sigAlgoID cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !tbsCRL.ReadAnyASN1Element(&sigAlgoID, &tag) {
		return x509asn1.ParamsState{}
	}

	return x509asn1.ParseAlgorithmIDParams(sigAlgoID)
}
