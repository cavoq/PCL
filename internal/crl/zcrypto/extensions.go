package zcrypto

import (
	"fmt"
	"math/big"
	"time"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type ExtensionFacts struct {
	OID      string
	Critical bool
	RawValue []byte
}

type IntegerExtensionFacts struct {
	Critical bool
	RawDER   []byte
	Value    x509ext.NonNegativeInteger
}

type AuthorityKeyIdentifierFacts struct {
	Critical        bool
	RawDER          []byte
	KeyIdentifier   []byte
	AuthorityIssuer []x509ext.GeneralName
	SerialNumber    *x509ext.NonNegativeInteger
}

type IssuingDistributionPointFacts struct {
	Critical                   bool
	RawDER                     []byte
	DistributionPoint          *x509ext.DistributionPointName
	OnlyContainsUserCerts      bool
	OnlyContainsCACerts        bool
	OnlySomeReasons            *x509ext.ReasonFlags
	IndirectCRL                bool
	OnlyContainsAttributeCerts bool
}

type DistributionPointsExtensionFacts struct {
	Critical bool
	RawDER   []byte
	Points   []x509ext.DistributionPoint
}

// CRLReason is the CRL entry reasonCode ENUMERATED value. It is deliberately
// distinct from x509ext.ReasonMask: value 8 here is removeFromCRL, while wire
// bit 8 in ReasonFlags is aACompromise.
type CRLReason int

const (
	CRLReasonUnspecified          CRLReason = 0
	CRLReasonKeyCompromise        CRLReason = 1
	CRLReasonCACompromise         CRLReason = 2
	CRLReasonAffiliationChanged   CRLReason = 3
	CRLReasonSuperseded           CRLReason = 4
	CRLReasonCessationOfOperation CRLReason = 5
	CRLReasonCertificateHold      CRLReason = 6
	CRLReasonRemoveFromCRL        CRLReason = 8
	CRLReasonPrivilegeWithdrawn   CRLReason = 9
	CRLReasonAACompromise         CRLReason = 10
)

type ReasonCodeExtensionFacts struct {
	Critical bool
	RawDER   []byte
	Value    CRLReason
}

type InvalidityDateExtensionFacts struct {
	Critical bool
	RawDER   []byte
	Value    time.Time
	Encoding x509asn1.TimeEncoding
}

type CertificateIssuerExtensionFacts struct {
	Critical bool
	RawDER   []byte
	Names    []x509ext.GeneralName
}

type EntryFacts struct {
	RawDER                           []byte
	SerialNumber                     *big.Int
	RevocationTime                   time.Time
	Extensions                       []ExtensionFacts
	ReasonCode                       *ReasonCodeExtensionFacts
	InvalidityDate                   *InvalidityDateExtensionFacts
	CertificateIssuer                *CertificateIssuerExtensionFacts
	UnsupportedCriticalExtensionOIDs []string
}

type RevocationListFacts struct {
	Extensions                       []ExtensionFacts
	AuthorityKeyIdentifier           *AuthorityKeyIdentifierFacts
	CRLNumber                        *IntegerExtensionFacts
	DeltaCRLIndicator                *IntegerExtensionFacts
	IssuingDistributionPoint         *IssuingDistributionPointFacts
	FreshestCRL                      *DistributionPointsExtensionFacts
	Entries                          []EntryFacts
	UnsupportedCriticalExtensionOIDs []string
}

// DecodeRevocationListStrict decodes every P3-supported CRL and CRL-entry
// extension. Duplicate OIDs and malformed implemented values are errors;
// unsupported critical extensions are returned explicitly for fail-closed
// domain processing.
func DecodeRevocationListStrict(list *x509.RevocationList) (RevocationListFacts, error) {
	if list == nil {
		return RevocationListFacts{}, fmt.Errorf("revocation list is nil")
	}

	facts := RevocationListFacts{}
	seen := make(map[string]struct{}, len(list.Extensions))
	for _, extension := range list.Extensions {
		identifier := extension.Id.String()
		if _, duplicate := seen[identifier]; duplicate {
			return RevocationListFacts{}, fmt.Errorf("duplicate CRL extension %s", identifier)
		}
		seen[identifier] = struct{}{}
		facts.Extensions = append(facts.Extensions, extensionFacts(extension))
		if extension.Critical && !oid.ExtensionProcessableAt(identifier, oid.ExtensionInCRL) {
			facts.UnsupportedCriticalExtensionOIDs = append(
				facts.UnsupportedCriticalExtensionOIDs,
				identifier,
			)
		}

		var err error
		switch identifier {
		case oid.AuthorityKeyIdentifier:
			facts.AuthorityKeyIdentifier, err = decodeAuthorityKeyIdentifierExtension(extension)
		case oid.CRLNumber:
			facts.CRLNumber, err = decodeIntegerExtension(extension)
		case oid.DeltaCRLIndicator:
			facts.DeltaCRLIndicator, err = decodeIntegerExtension(extension)
		case oid.IssuingDistributionPoint:
			facts.IssuingDistributionPoint, err = decodeIssuingDistributionPointExtension(extension)
		case oid.FreshestCRL:
			facts.FreshestCRL, err = decodeDistributionPointsExtension(extension)
		}
		if err != nil {
			return RevocationListFacts{}, fmt.Errorf("decode CRL extension %s: %w", identifier, err)
		}
	}

	facts.Entries = make([]EntryFacts, 0, len(list.RevokedCertificates))
	for index, entry := range list.RevokedCertificates {
		decoded, err := decodeEntryStrict(entry)
		if err != nil {
			return RevocationListFacts{}, fmt.Errorf("decode CRL entry %d: %w", index, err)
		}
		facts.Entries = append(facts.Entries, decoded)
	}
	return facts, nil
}

func extensionFacts(extension pkix.Extension) ExtensionFacts {
	return ExtensionFacts{
		OID:      extension.Id.String(),
		Critical: extension.Critical,
		RawValue: append([]byte(nil), extension.Value...),
	}
}

func decodeEntryStrict(entry x509.RevokedCertificate) (EntryFacts, error) {
	facts := EntryFacts{
		RawDER:         append([]byte(nil), entry.Raw...),
		RevocationTime: entry.RevocationTime,
	}
	if entry.SerialNumber != nil {
		facts.SerialNumber = new(big.Int).Set(entry.SerialNumber)
	}
	seen := make(map[string]struct{}, len(entry.Extensions))
	for _, extension := range entry.Extensions {
		identifier := extension.Id.String()
		if _, duplicate := seen[identifier]; duplicate {
			return EntryFacts{}, fmt.Errorf("duplicate CRL-entry extension %s", identifier)
		}
		seen[identifier] = struct{}{}
		facts.Extensions = append(facts.Extensions, extensionFacts(extension))
		if extension.Critical && !oid.ExtensionProcessableAt(identifier, oid.ExtensionInCRLEntry) {
			facts.UnsupportedCriticalExtensionOIDs = append(
				facts.UnsupportedCriticalExtensionOIDs,
				identifier,
			)
		}

		var err error
		switch identifier {
		case oid.CRLReason:
			facts.ReasonCode, err = decodeReasonCodeExtension(extension)
		case oid.InvalidityDate:
			facts.InvalidityDate, err = decodeInvalidityDateExtension(extension)
		case oid.CertificateIssuer:
			facts.CertificateIssuer, err = decodeCertificateIssuerExtension(extension)
		}
		if err != nil {
			return EntryFacts{}, fmt.Errorf("decode extension %s: %w", identifier, err)
		}
	}
	return facts, nil
}

func decodeIntegerExtension(extension pkix.Extension) (*IntegerExtensionFacts, error) {
	value, err := x509ext.DecodeNonNegativeInteger(extension.Value)
	if err != nil {
		return nil, err
	}
	return &IntegerExtensionFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
		Value:    value,
	}, nil
}

func decodeAuthorityKeyIdentifierExtension(
	extension pkix.Extension,
) (*AuthorityKeyIdentifierFacts, error) {
	input := cryptobyte.String(extension.Value)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid AuthorityKeyIdentifier sequence")
	}
	decoded := &AuthorityKeyIdentifierFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
	}
	lastTag := -1
	for !sequence.Empty() {
		var raw cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !sequence.ReadAnyASN1Element(&raw, &tag) {
			return nil, fmt.Errorf("invalid AuthorityKeyIdentifier field")
		}
		tagNumber := int(tag) & 0x1f
		if int(tag)&0xc0 != 0x80 || tagNumber <= lastTag || tagNumber > 2 {
			return nil, fmt.Errorf("duplicate, out-of-order, or unknown AuthorityKeyIdentifier field")
		}
		lastTag = tagNumber
		element := raw
		var content cryptobyte.String
		var parsedTag cryptobyte_asn1.Tag
		if !element.ReadAnyASN1(&content, &parsedTag) || !element.Empty() || parsedTag != tag {
			return nil, fmt.Errorf("invalid AuthorityKeyIdentifier field")
		}
		if err := decoded.decodeField(tagNumber, tag, raw, content); err != nil {
			return nil, err
		}
	}
	if (decoded.AuthorityIssuer != nil) != (decoded.SerialNumber != nil) {
		return nil, fmt.Errorf(
			"authorityCertIssuer and authorityCertSerialNumber must appear together",
		)
	}
	return decoded, nil
}

// decodeField stores one AuthorityKeyIdentifier field identified by
// tagNumber, after checking the tag form the field requires.
func (decoded *AuthorityKeyIdentifierFacts) decodeField(
	tagNumber int,
	tag cryptobyte_asn1.Tag,
	raw, content cryptobyte.String,
) error {
	switch tagNumber {
	case 0:
		if tag != cryptobyte_asn1.Tag(0).ContextSpecific() {
			return fmt.Errorf("invalid keyIdentifier tag")
		}
		decoded.KeyIdentifier = append([]byte(nil), content...)
	case 1:
		if tag != cryptobyte_asn1.Tag(1).ContextSpecific().Constructed() || content.Empty() {
			return fmt.Errorf("invalid authorityCertIssuer")
		}
		names, err := x509ext.ReadGeneralNamesContents(&content)
		if err != nil || len(names) == 0 {
			return fmt.Errorf("invalid authorityCertIssuer")
		}
		decoded.AuthorityIssuer = names
	case 2:
		if tag != cryptobyte_asn1.Tag(2).ContextSpecific() {
			return fmt.Errorf("invalid authorityCertSerialNumber tag")
		}
		serial, err := x509ext.DecodeNonNegativeIntegerContent(content)
		if err != nil {
			return fmt.Errorf("invalid authorityCertSerialNumber: %w", err)
		}
		serial.RawDER = append([]byte(nil), raw...)
		decoded.SerialNumber = &serial
	}
	return nil
}

func decodeIssuingDistributionPointExtension(
	extension pkix.Extension,
) (*IssuingDistributionPointFacts, error) {
	input := cryptobyte.String(extension.Value)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid IssuingDistributionPoint sequence")
	}
	decoded := &IssuingDistributionPointFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
	}
	lastTag := -1
	for !sequence.Empty() {
		var content cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !sequence.ReadAnyASN1(&content, &tag) {
			return nil, fmt.Errorf("invalid IssuingDistributionPoint field")
		}
		tagNumber := int(tag) & 0x1f
		if int(tag)&0xc0 != 0x80 || tagNumber <= lastTag || tagNumber > 5 {
			return nil, fmt.Errorf("duplicate, out-of-order, or unknown IssuingDistributionPoint field")
		}
		lastTag = tagNumber
		if err := decoded.decodeField(tagNumber, tag, content); err != nil {
			return nil, err
		}
	}
	if err := decoded.validate(); err != nil {
		return nil, err
	}
	return decoded, nil
}

// decodeField stores one IssuingDistributionPoint field identified by
// tagNumber, after checking the tag form the field requires.
func (decoded *IssuingDistributionPointFacts) decodeField(
	tagNumber int,
	tag cryptobyte_asn1.Tag,
	content cryptobyte.String,
) error {
	switch tagNumber {
	case 0:
		if tag != cryptobyte_asn1.Tag(0).ContextSpecific().Constructed() {
			return fmt.Errorf("invalid distributionPoint tag")
		}
		name, err := x509ext.DecodeDistributionPointNameContents(content)
		if err != nil {
			return err
		}
		decoded.DistributionPoint = &name
	case 1, 2, 4, 5:
		// DEFAULT FALSE booleans may only be encoded when TRUE.
		if tag != cryptobyte_asn1.Tag(tagNumber).ContextSpecific() || len(content) != 1 || content[0] != 0xff {
			return fmt.Errorf("invalid or explicitly false DEFAULT boolean field %d", tagNumber)
		}
		*decoded.booleanField(tagNumber) = true
	case 3:
		if tag != cryptobyte_asn1.Tag(3).ContextSpecific() {
			return fmt.Errorf("invalid onlySomeReasons tag")
		}
		reasons, err := x509ext.DecodeReasonFlagsContents(content)
		if err != nil {
			return err
		}
		decoded.OnlySomeReasons = &reasons
	}
	return nil
}

func (decoded *IssuingDistributionPointFacts) booleanField(tagNumber int) *bool {
	switch tagNumber {
	case 1:
		return &decoded.OnlyContainsUserCerts
	case 2:
		return &decoded.OnlyContainsCACerts
	case 4:
		return &decoded.IndirectCRL
	default:
		return &decoded.OnlyContainsAttributeCerts
	}
}

// validate checks the cross-field rules: at most one onlyContains scope and
// at least one field present.
func (decoded *IssuingDistributionPointFacts) validate() error {
	scopeBooleans := 0
	for _, asserted := range []bool{
		decoded.OnlyContainsUserCerts,
		decoded.OnlyContainsCACerts,
		decoded.OnlyContainsAttributeCerts,
	} {
		if asserted {
			scopeBooleans++
		}
	}
	if scopeBooleans > 1 {
		return fmt.Errorf("multiple onlyContains scope booleans are asserted")
	}
	if decoded.DistributionPoint == nil && decoded.OnlySomeReasons == nil &&
		!decoded.OnlyContainsUserCerts && !decoded.OnlyContainsCACerts &&
		!decoded.IndirectCRL && !decoded.OnlyContainsAttributeCerts {
		return fmt.Errorf("IssuingDistributionPoint must not be empty")
	}
	return nil
}

func decodeDistributionPointsExtension(
	extension pkix.Extension,
) (*DistributionPointsExtensionFacts, error) {
	points, err := x509ext.DecodeDistributionPoints(extension.Value)
	if err != nil {
		return nil, err
	}
	for index, point := range points {
		if point.Reasons != nil || point.CRLIssuer != nil {
			return nil, fmt.Errorf(
				"CRL Freshest distribution point %d contains reasons or cRLIssuer",
				index,
			)
		}
	}
	return &DistributionPointsExtensionFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
		Points:   points,
	}, nil
}

func decodeReasonCodeExtension(extension pkix.Extension) (*ReasonCodeExtensionFacts, error) {
	input := cryptobyte.String(extension.Value)
	var value int
	if !input.ReadASN1Enum(&value) || !input.Empty() || !validCRLReason(value) {
		return nil, fmt.Errorf("invalid reasonCode ENUMERATED")
	}
	return &ReasonCodeExtensionFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
		Value:    CRLReason(value),
	}, nil
}

func validCRLReason(value int) bool {
	return value >= 0 && value <= 10 && value != 7
}

func decodeInvalidityDateExtension(
	extension pkix.Extension,
) (*InvalidityDateExtensionFacts, error) {
	encoding, err := x509asn1.ParseGeneralizedTime(extension.Value)
	if err != nil || !encoding.HasSeconds || encoding.HasFraction || !encoding.HasZulu {
		return nil, fmt.Errorf("invalid invalidityDate GeneralizedTime")
	}
	input := cryptobyte.String(extension.Value)
	var value time.Time
	if !input.ReadASN1GeneralizedTime(&value) || !input.Empty() {
		return nil, fmt.Errorf("invalid invalidityDate GeneralizedTime")
	}
	return &InvalidityDateExtensionFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
		Value:    value,
		Encoding: *encoding,
	}, nil
}

func decodeCertificateIssuerExtension(
	extension pkix.Extension,
) (*CertificateIssuerExtensionFacts, error) {
	names, err := x509ext.DecodeGeneralNames(extension.Value)
	if err != nil {
		return nil, err
	}
	return &CertificateIssuerExtensionFacts{
		Critical: extension.Critical,
		RawDER:   append([]byte(nil), extension.Value...),
		Names:    names,
	}, nil
}
