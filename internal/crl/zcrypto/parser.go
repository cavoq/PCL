package zcrypto

import (
	"github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
)

// AuthorityKeyIdentifier returns the semantic keyIdentifier from the CRL AKI
// extension. zcrypto currently exposes RevocationList.AuthorityKeyId as the
// complete extension value, so callers must not compare that field directly
// with a certificate SubjectKeyId.
func AuthorityKeyIdentifier(crl *x509.RevocationList) []byte {
	if crl == nil {
		return nil
	}

	for _, extension := range crl.Extensions {
		if extension.Id.String() != oid.AuthorityKeyIdentifier {
			continue
		}
		facts, err := decodeAuthorityKeyIdentifierExtension(extension)
		if err != nil {
			return nil
		}
		return append([]byte(nil), facts.KeyIdentifier...)
	}

	// Manually constructed RevocationList values used by callers may already
	// contain the semantic key identifier and have no raw extension list.
	return append([]byte(nil), crl.AuthorityKeyId...)
}

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
