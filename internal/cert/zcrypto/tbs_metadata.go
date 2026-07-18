package zcrypto

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
)

type tbsCertificateMetadata struct {
	SerialNumber    integerMetadata
	Validity        validityMetadata
	IssuerUniqueID  *uniqueIdentifierMetadata
	SubjectUniqueID *uniqueIdentifierMetadata
}

type integerMetadata struct {
	RawDER []byte
	Value  []byte
}

type validityMetadata struct {
	NotBefore internalasn1.TimeEncoding
	NotAfter  internalasn1.TimeEncoding
}

type uniqueIdentifierMetadata struct {
	RawDER     []byte
	Value      []byte
	UnusedBits int
	BitLength  int
}

// parseTBSCertificateMetadata owns certificate-schema traversal for encoding
// facts that the decoded x509.Certificate cannot represent losslessly.
func parseTBSCertificateMetadata(rawTBSCertificate []byte) (tbsCertificateMetadata, error) {
	input := cryptobyte.String(rawTBSCertificate)
	var tbsCertificate cryptobyte.String
	if !input.ReadASN1(&tbsCertificate, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return tbsCertificateMetadata{}, fmt.Errorf("failed to read TBSCertificate")
	}

	if !tbsCertificate.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return tbsCertificateMetadata{}, fmt.Errorf("failed to read certificate version")
	}
	serialNumber, err := readIntegerMetadata(&tbsCertificate, "serialNumber")
	if err != nil {
		return tbsCertificateMetadata{}, err
	}

	for _, field := range []struct {
		name string
		tag  cryptobyte_asn1.Tag
	}{
		{name: "signature AlgorithmIdentifier", tag: cryptobyte_asn1.SEQUENCE},
		{name: "issuer", tag: cryptobyte_asn1.SEQUENCE},
	} {
		if !tbsCertificate.SkipASN1(field.tag) {
			return tbsCertificateMetadata{}, fmt.Errorf("failed to read %s", field.name)
		}
	}

	var validity cryptobyte.String
	if !tbsCertificate.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return tbsCertificateMetadata{}, fmt.Errorf("failed to read validity")
	}
	validityInfo, err := parseValidityMetadata(validity)
	if err != nil {
		return tbsCertificateMetadata{}, err
	}

	for _, field := range []string{"subject", "subjectPublicKeyInfo"} {
		if !tbsCertificate.SkipASN1(cryptobyte_asn1.SEQUENCE) {
			return tbsCertificateMetadata{}, fmt.Errorf("failed to read %s", field)
		}
	}

	issuerUniqueID, err := readOptionalUniqueIdentifier(
		&tbsCertificate,
		"issuerUniqueID",
		cryptobyte_asn1.Tag(1).ContextSpecific(),
	)
	if err != nil {
		return tbsCertificateMetadata{}, err
	}
	subjectUniqueID, err := readOptionalUniqueIdentifier(
		&tbsCertificate,
		"subjectUniqueID",
		cryptobyte_asn1.Tag(2).ContextSpecific(),
	)
	if err != nil {
		return tbsCertificateMetadata{}, err
	}

	if !tbsCertificate.SkipOptionalASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
		return tbsCertificateMetadata{}, fmt.Errorf("failed to read extensions")
	}
	if !tbsCertificate.Empty() {
		return tbsCertificateMetadata{}, fmt.Errorf("unexpected data after TBSCertificate fields")
	}

	return tbsCertificateMetadata{
		SerialNumber:    serialNumber,
		Validity:        validityInfo,
		IssuerUniqueID:  issuerUniqueID,
		SubjectUniqueID: subjectUniqueID,
	}, nil
}

func readIntegerMetadata(input *cryptobyte.String, field string) (integerMetadata, error) {
	var rawDER cryptobyte.String
	if !input.ReadASN1Element(&rawDER, cryptobyte_asn1.INTEGER) {
		return integerMetadata{}, fmt.Errorf("failed to read %s", field)
	}

	element := cryptobyte.String(rawDER)
	var value cryptobyte.String
	if !element.ReadASN1(&value, cryptobyte_asn1.INTEGER) || !element.Empty() || value.Empty() {
		return integerMetadata{}, fmt.Errorf("invalid %s", field)
	}
	return integerMetadata{
		RawDER: append([]byte(nil), rawDER...),
		Value:  append([]byte(nil), value...),
	}, nil
}

func parseValidityMetadata(validity cryptobyte.String) (validityMetadata, error) {
	notBefore, err := readValidityTime(&validity, "notBefore")
	if err != nil {
		return validityMetadata{}, err
	}
	notAfter, err := readValidityTime(&validity, "notAfter")
	if err != nil {
		return validityMetadata{}, err
	}
	if !validity.Empty() {
		return validityMetadata{}, fmt.Errorf("unexpected data after notAfter")
	}
	return validityMetadata{NotBefore: notBefore, NotAfter: notAfter}, nil
}

func readValidityTime(validity *cryptobyte.String, field string) (internalasn1.TimeEncoding, error) {
	var der cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !validity.ReadAnyASN1Element(&der, &tag) {
		return internalasn1.TimeEncoding{}, fmt.Errorf("failed to read %s", field)
	}

	var (
		info *internalasn1.TimeEncoding
		err  error
	)
	switch tag {
	case cryptobyte_asn1.UTCTime:
		info, err = internalasn1.ParseUTCTime(der)
	case cryptobyte_asn1.GeneralizedTime:
		info, err = internalasn1.ParseGeneralizedTime(der)
	default:
		return internalasn1.TimeEncoding{}, fmt.Errorf("unsupported %s tag %d", field, tag)
	}
	if err != nil {
		return internalasn1.TimeEncoding{}, fmt.Errorf("parse %s: %w", field, err)
	}
	return *info, nil
}

func readOptionalUniqueIdentifier(
	input *cryptobyte.String,
	field string,
	tag cryptobyte_asn1.Tag,
) (*uniqueIdentifierMetadata, error) {
	if !input.PeekASN1Tag(tag) {
		return nil, nil
	}

	var rawDER cryptobyte.String
	if !input.ReadASN1Element(&rawDER, tag) {
		return nil, fmt.Errorf("failed to read %s", field)
	}
	metadata, err := parseUniqueIdentifier(rawDER, tag)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", field, err)
	}
	return &metadata, nil
}

func parseUniqueIdentifier(rawDER []byte, tag cryptobyte_asn1.Tag) (uniqueIdentifierMetadata, error) {
	input := cryptobyte.String(rawDER)
	var encoded cryptobyte.String
	if !input.ReadASN1(&encoded, tag) || !input.Empty() || len(encoded) == 0 {
		return uniqueIdentifierMetadata{}, fmt.Errorf("invalid BIT STRING encoding")
	}

	unusedBits := int(encoded[0])
	value := encoded[1:]
	if unusedBits > 7 || (len(value) == 0 && unusedBits != 0) {
		return uniqueIdentifierMetadata{}, fmt.Errorf("invalid unused-bit count")
	}
	if unusedBits > 0 && value[len(value)-1]&byte((1<<unusedBits)-1) != 0 {
		return uniqueIdentifierMetadata{}, fmt.Errorf("non-zero unused bits")
	}

	return uniqueIdentifierMetadata{
		RawDER:     append([]byte(nil), rawDER...),
		Value:      append([]byte(nil), value...),
		UnusedBits: unusedBits,
		BitLength:  len(value)*8 - unusedBits,
	}, nil
}
