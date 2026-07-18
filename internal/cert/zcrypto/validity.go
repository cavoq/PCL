package zcrypto

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/asn1"
)

type validityEncodingInfo struct {
	NotBefore asn1.TimeFormatInfo
	NotAfter  asn1.TimeFormatInfo
}

// parseValidityEncoding locates the validity period in a TBSCertificate and
// preserves the DER time format used for each endpoint. Semantic time values
// remain owned by x509.Certificate.NotBefore and NotAfter.
func parseValidityEncoding(rawTBSCertificate []byte) (validityEncodingInfo, error) {
	validity, err := readValiditySequence(rawTBSCertificate)
	if err != nil {
		return validityEncodingInfo{}, err
	}

	notBefore, err := readValidityTime(&validity, "notBefore")
	if err != nil {
		return validityEncodingInfo{}, err
	}
	notAfter, err := readValidityTime(&validity, "notAfter")
	if err != nil {
		return validityEncodingInfo{}, err
	}
	if !validity.Empty() {
		return validityEncodingInfo{}, fmt.Errorf("unexpected data after notAfter")
	}

	return validityEncodingInfo{NotBefore: notBefore, NotAfter: notAfter}, nil
}

func readValiditySequence(rawTBSCertificate []byte) (cryptobyte.String, error) {
	input := cryptobyte.String(rawTBSCertificate)
	var tbsCertificate cryptobyte.String
	if !input.ReadASN1(&tbsCertificate, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("failed to read TBSCertificate")
	}
	if !tbsCertificate.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, fmt.Errorf("failed to read certificate version")
	}
	if !tbsCertificate.SkipASN1(cryptobyte_asn1.INTEGER) {
		return nil, fmt.Errorf("failed to read serialNumber")
	}
	if !tbsCertificate.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read signature AlgorithmIdentifier")
	}
	if !tbsCertificate.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read issuer")
	}

	var validity cryptobyte.String
	if !tbsCertificate.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read validity")
	}
	return validity, nil
}

func readValidityTime(validity *cryptobyte.String, field string) (asn1.TimeFormatInfo, error) {
	var der cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !validity.ReadAnyASN1Element(&der, &tag) {
		return asn1.TimeFormatInfo{}, fmt.Errorf("failed to read %s", field)
	}

	var (
		info *asn1.TimeFormatInfo
		err  error
	)
	switch tag {
	case cryptobyte_asn1.UTCTime:
		info, err = asn1.ParseUTCTime(der)
	case cryptobyte_asn1.GeneralizedTime:
		info, err = asn1.ParseGeneralizedTime(der)
	default:
		return asn1.TimeFormatInfo{}, fmt.Errorf("unsupported %s tag %d", field, tag)
	}
	if err != nil {
		return asn1.TimeFormatInfo{}, fmt.Errorf("parse %s: %w", field, err)
	}
	return *info, nil
}
