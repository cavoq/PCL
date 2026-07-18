package zcrypto

import (
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

// parseTBSCertSignatureParams locates the signature AlgorithmIdentifier in a
// TBSCertificate. Its position is certificate-schema-specific, so traversal
// remains in the certificate adapter.
func parseTBSCertSignatureParams(rawTBSCertificate []byte) asn1.ParamsState {
	if len(rawTBSCertificate) == 0 {
		return asn1.ParamsState{}
	}
	input := cryptobyte.String(rawTBSCertificate)
	var tbsCertificate cryptobyte.String
	if !input.ReadASN1(&tbsCertificate, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return asn1.ParamsState{Malformed: true}
	}
	if !tbsCertificate.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbsCertificate.SkipASN1(cryptobyte_asn1.INTEGER) {
		return asn1.ParamsState{Malformed: true}
	}

	var algorithmDER cryptobyte.String
	if !tbsCertificate.ReadASN1Element(&algorithmDER, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{Malformed: true}
	}
	return asn1.ParseAlgorithmIDParams(algorithmDER)
}

// parseSubjectPublicKeyInfoParams locates the AlgorithmIdentifier in a
// SubjectPublicKeyInfo value.
func parseSubjectPublicKeyInfoParams(rawSubjectPublicKeyInfo []byte) asn1.ParamsState {
	if len(rawSubjectPublicKeyInfo) == 0 {
		return asn1.ParamsState{}
	}
	input := cryptobyte.String(rawSubjectPublicKeyInfo)
	var subjectPublicKeyInfo cryptobyte.String
	if !input.ReadASN1(&subjectPublicKeyInfo, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return asn1.ParamsState{Malformed: true}
	}

	var algorithmDER cryptobyte.String
	if !subjectPublicKeyInfo.ReadASN1Element(&algorithmDER, cryptobyte_asn1.SEQUENCE) {
		return asn1.ParamsState{Malformed: true}
	}
	return asn1.ParseAlgorithmIDParams(algorithmDER)
}
