package x509ext

import (
	"bytes"
	"fmt"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type DistributionPointNameKind string

const (
	DistributionPointNameFullName DistributionPointNameKind = "fullName"
	DistributionPointNameRelative DistributionPointNameKind = "nameRelativeToCRLIssuer"
)

type DistributionPointName struct {
	Kind        DistributionPointNameKind
	FullName    []GeneralName
	RelativeRDN []byte
	// RelativeNameDER is RelativeRDN wrapped as a single-RDN Name, the form
	// accepted by name parsers and projections.
	RelativeNameDER []byte
	RawDER          []byte
}

type DistributionPoint struct {
	Name      *DistributionPointName
	Reasons   *ReasonFlags
	CRLIssuer []GeneralName
	RawDER    []byte
}

// DecodeDistributionPoints decodes exactly one non-empty
// CRLDistributionPoints value. It is shared by cRLDistributionPoints and
// Freshest CRL at certificate and CRL locations.
func DecodeDistributionPoints(der []byte) ([]DistributionPoint, error) {
	input := cryptobyte.String(der)
	var encodedPoints cryptobyte.String
	if !input.ReadASN1(&encodedPoints, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid CRLDistributionPoints sequence")
	}
	if encodedPoints.Empty() {
		return nil, fmt.Errorf("CRLDistributionPoints must not be empty")
	}

	var points []DistributionPoint
	for index := 0; !encodedPoints.Empty(); index++ {
		var raw cryptobyte.String
		if !encodedPoints.ReadASN1Element(&raw, cryptobyte_asn1.SEQUENCE) {
			return nil, fmt.Errorf("invalid DistributionPoint %d", index)
		}
		element := raw
		var contents cryptobyte.String
		if !element.ReadASN1(&contents, cryptobyte_asn1.SEQUENCE) || !element.Empty() {
			return nil, fmt.Errorf("invalid DistributionPoint %d", index)
		}
		point, err := decodeDistributionPoint(contents, index)
		if err != nil {
			return nil, err
		}
		point.RawDER = append([]byte(nil), raw...)
		points = append(points, point)
	}
	return points, nil
}

func decodeDistributionPoint(encoded cryptobyte.String, index int) (DistributionPoint, error) {
	var decoded DistributionPoint
	lastTag := -1
	for !encoded.Empty() {
		var field cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !encoded.ReadAnyASN1(&field, &tag) {
			return DistributionPoint{}, fmt.Errorf("invalid field in DistributionPoint %d", index)
		}
		contextTag := int(tag) & 0x1f
		if int(tag)&0xc0 != 0x80 || contextTag <= lastTag {
			return DistributionPoint{}, fmt.Errorf(
				"duplicate, out-of-order, or invalid field in DistributionPoint %d",
				index,
			)
		}
		lastTag = contextTag

		switch contextTag {
		case 0:
			if tag != cryptobyte_asn1.Tag(0).ContextSpecific().Constructed() {
				return DistributionPoint{}, fmt.Errorf("invalid distributionPoint tag in DistributionPoint %d", index)
			}
			name, err := DecodeDistributionPointNameContents(field)
			if err != nil {
				return DistributionPoint{}, fmt.Errorf("invalid DistributionPointName in DistributionPoint %d: %w", index, err)
			}
			decoded.Name = &name
		case 1:
			if tag != cryptobyte_asn1.Tag(1).ContextSpecific() {
				return DistributionPoint{}, fmt.Errorf("invalid reasons tag in DistributionPoint %d", index)
			}
			reasons, err := DecodeReasonFlagsContents(field)
			if err != nil {
				return DistributionPoint{}, fmt.Errorf("invalid reasons in DistributionPoint %d: %w", index, err)
			}
			decoded.Reasons = &reasons
		case 2:
			if tag != cryptobyte_asn1.Tag(2).ContextSpecific().Constructed() || field.Empty() {
				return DistributionPoint{}, fmt.Errorf("invalid cRLIssuer in DistributionPoint %d", index)
			}
			issuer, err := ReadGeneralNamesContents(&field)
			if err != nil || len(issuer) == 0 {
				return DistributionPoint{}, fmt.Errorf("invalid cRLIssuer in DistributionPoint %d", index)
			}
			decoded.CRLIssuer = issuer
		default:
			return DistributionPoint{}, fmt.Errorf("unknown field in DistributionPoint %d", index)
		}
	}
	if decoded.Name == nil && decoded.CRLIssuer == nil {
		return DistributionPoint{}, fmt.Errorf(
			"DistributionPoint %d has neither distributionPoint nor cRLIssuer",
			index,
		)
	}
	return decoded, nil
}

// DecodeDistributionPointNameContents decodes the body of the explicit
// distributionPoint [0] field in a DistributionPoint or IDP.
func DecodeDistributionPointNameContents(encoded cryptobyte.String) (DistributionPointName, error) {
	var raw cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !encoded.ReadAnyASN1Element(&raw, &tag) || !encoded.Empty() {
		return DistributionPointName{}, fmt.Errorf("invalid DistributionPointName")
	}
	element := raw
	var value cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&value, &parsedTag) || !element.Empty() || parsedTag != tag {
		return DistributionPointName{}, fmt.Errorf("invalid DistributionPointName")
	}

	switch tag {
	case cryptobyte_asn1.Tag(0).ContextSpecific().Constructed():
		if value.Empty() {
			return DistributionPointName{}, fmt.Errorf("empty fullName")
		}
		names, err := ReadGeneralNamesContents(&value)
		if err != nil || len(names) == 0 {
			return DistributionPointName{}, fmt.Errorf("invalid fullName")
		}
		return DistributionPointName{
			Kind:     DistributionPointNameFullName,
			FullName: names,
			RawDER:   append([]byte(nil), raw...),
		}, nil
	case cryptobyte_asn1.Tag(1).ContextSpecific().Constructed():
		if value.Empty() {
			return DistributionPointName{}, fmt.Errorf("empty nameRelativeToCRLIssuer")
		}
		rdnDER, nameDER, err := encodeRelativeDistinguishedName(value)
		if err != nil {
			return DistributionPointName{}, err
		}
		parsed, err := internalasn1.ParseDistinguishedNameStrict(nameDER)
		if err != nil || len(parsed.RDNs) != 1 {
			return DistributionPointName{}, fmt.Errorf("invalid nameRelativeToCRLIssuer")
		}
		return DistributionPointName{
			Kind:            DistributionPointNameRelative,
			RelativeRDN:     rdnDER,
			RelativeNameDER: nameDER,
			RawDER:          append([]byte(nil), raw...),
		}, nil
	default:
		return DistributionPointName{}, fmt.Errorf("unknown DistributionPointName")
	}
}

func encodeRelativeDistinguishedName(contents []byte) ([]byte, []byte, error) {
	var rdnBuilder cryptobyte.Builder
	rdnBuilder.AddASN1(cryptobyte_asn1.SET, func(builder *cryptobyte.Builder) {
		builder.AddBytes(contents)
	})
	rdnDER, err := rdnBuilder.Bytes()
	if err != nil {
		return nil, nil, err
	}
	var nameBuilder cryptobyte.Builder
	nameBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddBytes(rdnDER)
	})
	nameDER, err := nameBuilder.Bytes()
	return rdnDER, nameDER, err
}

func DistributionPointURIs(points []DistributionPoint) []string {
	seen := make(map[string]struct{})
	var uris []string
	for _, point := range points {
		if point.Name == nil || point.Name.Kind != DistributionPointNameFullName {
			continue
		}
		for _, name := range point.Name.FullName {
			if name.Tag != 6 {
				continue
			}
			uri := string(name.RawValue)
			if _, duplicate := seen[uri]; duplicate {
				continue
			}
			seen[uri] = struct{}{}
			uris = append(uris, uri)
		}
	}
	return uris
}

// ExpandDistributionPointName returns its GeneralNames representation.
// Relative names are appended to baseNameDER, which must encode a Name.
func ExpandDistributionPointName(name *DistributionPointName, baseNameDER []byte) ([]GeneralName, error) {
	if name == nil {
		return nil, fmt.Errorf("distribution point name is absent")
	}
	if name.Kind == DistributionPointNameFullName {
		return cloneGeneralNames(name.FullName), nil
	}
	if name.Kind != DistributionPointNameRelative || len(name.RelativeRDN) == 0 {
		return nil, fmt.Errorf("invalid relative distribution point name")
	}
	if _, err := internalasn1.ParseDistinguishedNameStrict(baseNameDER); err != nil {
		return nil, fmt.Errorf("invalid distribution point base Name: %w", err)
	}
	base := cryptobyte.String(baseNameDER)
	var rdns cryptobyte.String
	if !base.ReadASN1(&rdns, cryptobyte_asn1.SEQUENCE) || !base.Empty() {
		return nil, fmt.Errorf("invalid distribution point base Name")
	}
	var nameBuilder cryptobyte.Builder
	nameBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddBytes(rdns)
		builder.AddBytes(name.RelativeRDN)
	})
	nameDER, err := nameBuilder.Bytes()
	if err != nil {
		return nil, err
	}
	var generalNameBuilder cryptobyte.Builder
	generalNameBuilder.AddASN1(
		cryptobyte_asn1.Tag(4).ContextSpecific().Constructed(),
		func(builder *cryptobyte.Builder) { builder.AddBytes(nameDER) },
	)
	generalNameDER, err := generalNameBuilder.Bytes()
	if err != nil {
		return nil, err
	}
	return []GeneralName{{
		Tag:      4,
		RawDER:   generalNameDER,
		RawValue: nameDER,
	}}, nil
}

func DistributionPointNamesIntersect(
	left, right *DistributionPointName,
	leftBaseDER, rightBaseDER []byte,
) bool {
	leftNames, err := ExpandDistributionPointName(left, leftBaseDER)
	if err != nil {
		return false
	}
	rightNames, err := ExpandDistributionPointName(right, rightBaseDER)
	if err != nil {
		return false
	}
	for _, leftName := range leftNames {
		for _, rightName := range rightNames {
			if bytes.Equal(leftName.RawDER, rightName.RawDER) {
				return true
			}
		}
	}
	return false
}

func cloneGeneralNames(names []GeneralName) []GeneralName {
	cloned := make([]GeneralName, len(names))
	for i, name := range names {
		cloned[i] = GeneralName{
			Tag:      name.Tag,
			RawDER:   append([]byte(nil), name.RawDER...),
			RawValue: append([]byte(nil), name.RawValue...),
		}
	}
	return cloned
}
