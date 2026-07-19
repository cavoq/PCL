package zcrypto

import (
	"fmt"
	"strconv"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	nameprojector "github.com/cavoq/PCL/internal/zcrypto"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//
//	DistributionPoint ::= SEQUENCE {
//	    distributionPoint [0] DistributionPointName OPTIONAL,
//	    reasons           [1] ReasonFlags OPTIONAL,
//	    cRLIssuer         [2] GeneralNames OPTIONAL }
//
//	DistributionPointName ::= CHOICE {
//	    fullName                [0] GeneralNames,
//	    nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
type decodedDistributionPointNameKind uint8

const (
	decodedFullName decodedDistributionPointNameKind = iota
	decodedNameRelativeToCRLIssuer
)

type decodedDistributionPointName struct {
	Kind         decodedDistributionPointNameKind
	GeneralNames []parsedGeneralName
	RelativeName []byte
	RelativeRaw  []byte
}

type decodedCRLDistributionPoint struct {
	Name      *decodedDistributionPointName
	Reasons   *decodedReasonFlags
	CRLIssuer []parsedGeneralName
}

// CRLDistributionPointNameKind identifies the selected DistributionPointName
// alternative. The empty value means the optional field was absent.
type CRLDistributionPointNameKind string

const (
	CRLDistributionPointNameAbsent   CRLDistributionPointNameKind = ""
	CRLDistributionPointNameFullName CRLDistributionPointNameKind = "fullName"
	CRLDistributionPointNameRelative CRLDistributionPointNameKind = "nameRelativeToCRLIssuer"
)

// CRLDistributionPointsFacts is the typed adapter boundary used by
// certificate-profile predicates. It deliberately keeps profile dependencies
// out of the DER parser while retaining enough structure to enforce them.
type CRLDistributionPointsFacts struct {
	DistributionPoints []CRLDistributionPointFacts
}

type CRLDistributionPointFacts struct {
	DistributionPointPresent  bool
	DistributionPointNameKind CRLDistributionPointNameKind
	FullNameGeneralNameTags   []int
	ReasonsPresent            bool
	ReasonBits                []int
	CRLIssuerGeneralNameTags  []int
}

// ParseCRLDP parses the CRL Distribution Points extension and retains the
// compatibility behavior that projects malformed input as a node.
func ParseCRLDP(extValue []byte) *node.Node {
	n, err := ParseCRLDPStrict(extValue)
	if err == nil {
		return n
	}
	return malformedExtensionNode("cRLDistributionPoints", isEmptySequence(extValue))
}

// ParseCRLDPStrict parses exactly one CRLDistributionPoints value.
func ParseCRLDPStrict(extValue []byte) (*node.Node, error) {
	distributionPoints, err := decodeCRLDistributionPoints(extValue)
	if err != nil {
		return nil, err
	}
	return projectCRLDistributionPoints(distributionPoints), nil
}

// DecodeCRLDistributionPointsStrict returns strictly decoded structural facts
// without applying RFC 5280 profile dependencies such as the cRLIssuer name
// form restriction or the relative-name single-issuer rule.
func DecodeCRLDistributionPointsStrict(extValue []byte) (CRLDistributionPointsFacts, error) {
	decoded, err := decodeCRLDistributionPoints(extValue)
	if err != nil {
		return CRLDistributionPointsFacts{}, err
	}

	facts := CRLDistributionPointsFacts{
		DistributionPoints: make([]CRLDistributionPointFacts, 0, len(decoded)),
	}
	for _, distributionPoint := range decoded {
		pointFacts := CRLDistributionPointFacts{
			DistributionPointPresent: distributionPoint.Name != nil,
			ReasonsPresent:           distributionPoint.Reasons != nil,
		}
		if distributionPoint.Name != nil {
			switch distributionPoint.Name.Kind {
			case decodedFullName:
				pointFacts.DistributionPointNameKind = CRLDistributionPointNameFullName
				pointFacts.FullNameGeneralNameTags = generalNameTags(
					distributionPoint.Name.GeneralNames,
				)
			case decodedNameRelativeToCRLIssuer:
				pointFacts.DistributionPointNameKind = CRLDistributionPointNameRelative
			}
		}
		if distributionPoint.Reasons != nil {
			for _, definition := range reasonFlagDefinitions {
				if reasonFlagSet(distributionPoint.Reasons.Value, definition.Bit) {
					pointFacts.ReasonBits = append(pointFacts.ReasonBits, definition.Bit)
				}
			}
		}
		pointFacts.CRLIssuerGeneralNameTags = generalNameTags(distributionPoint.CRLIssuer)
		facts.DistributionPoints = append(facts.DistributionPoints, pointFacts)
	}
	return facts, nil
}

func generalNameTags(names []parsedGeneralName) []int {
	if names == nil {
		return nil
	}
	tags := make([]int, 0, len(names))
	for _, name := range names {
		tags = append(tags, name.Tag)
	}
	return tags
}

func decodeCRLDistributionPoints(extValue []byte) ([]decodedCRLDistributionPoint, error) {
	input := cryptobyte.String(extValue)
	var encodedDistributionPoints cryptobyte.String
	if !input.ReadASN1(&encodedDistributionPoints, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("invalid CRLDistributionPoints sequence")
	}
	if encodedDistributionPoints.Empty() {
		return nil, fmt.Errorf("CRLDistributionPoints must not be empty")
	}

	var distributionPoints []decodedCRLDistributionPoint
	for index := 0; !encodedDistributionPoints.Empty(); index++ {
		var encodedDistributionPoint cryptobyte.String
		if !encodedDistributionPoints.ReadASN1(&encodedDistributionPoint, cryptobyte_asn1.SEQUENCE) {
			return nil, fmt.Errorf("invalid DistributionPoint %d", index)
		}
		distributionPoint, err := decodeCRLDistributionPoint(encodedDistributionPoint, index)
		if err != nil {
			return nil, err
		}
		distributionPoints = append(distributionPoints, distributionPoint)
	}
	return distributionPoints, nil
}

func decodeCRLDistributionPoint(
	encoded cryptobyte.String,
	index int,
) (decodedCRLDistributionPoint, error) {
	var decoded decodedCRLDistributionPoint
	lastTag := -1

	for !encoded.Empty() {
		var field cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !encoded.ReadAnyASN1(&field, &tag) {
			return decodedCRLDistributionPoint{}, fmt.Errorf("invalid field in DistributionPoint %d", index)
		}

		contextTag := int(tag) & 0x1f
		if contextTag <= lastTag {
			return decodedCRLDistributionPoint{}, fmt.Errorf(
				"duplicate or out-of-order field in DistributionPoint %d",
				index,
			)
		}
		lastTag = contextTag

		switch contextTag {
		case 0:
			if tag != cryptobyte_asn1.Tag(0).ContextSpecific().Constructed() {
				return decodedCRLDistributionPoint{}, fmt.Errorf(
					"invalid distributionPoint tag in DistributionPoint %d",
					index,
				)
			}
			name, err := decodeDistributionPointName(field, index)
			if err != nil {
				return decodedCRLDistributionPoint{}, err
			}
			decoded.Name = &name

		case 1:
			if tag != cryptobyte_asn1.Tag(1).ContextSpecific() {
				return decodedCRLDistributionPoint{}, fmt.Errorf(
					"invalid reasons tag in DistributionPoint %d",
					index,
				)
			}
			reasons, err := decodeReasonFlags([]byte(field))
			if err != nil {
				return decodedCRLDistributionPoint{}, fmt.Errorf(
					"invalid reasons BIT STRING in DistributionPoint %d",
					index,
				)
			}
			decoded.Reasons = &reasons

		case 2:
			if tag != cryptobyte_asn1.Tag(2).ContextSpecific().Constructed() || field.Empty() {
				return decodedCRLDistributionPoint{}, fmt.Errorf(
					"invalid cRLIssuer in DistributionPoint %d",
					index,
				)
			}
			issuer, err := readGeneralNames(&field)
			if err != nil {
				return decodedCRLDistributionPoint{}, fmt.Errorf(
					"invalid cRLIssuer in DistributionPoint %d: %w",
					index,
					err,
				)
			}
			decoded.CRLIssuer = issuer

		default:
			return decodedCRLDistributionPoint{}, fmt.Errorf("unknown field in DistributionPoint %d", index)
		}
	}

	if decoded.Name == nil && decoded.CRLIssuer == nil {
		return decodedCRLDistributionPoint{}, fmt.Errorf(
			"DistributionPoint %d has neither distributionPoint nor cRLIssuer",
			index,
		)
	}
	return decoded, nil
}

func decodeDistributionPointName(
	encoded cryptobyte.String,
	index int,
) (decodedDistributionPointName, error) {
	var raw cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !encoded.ReadAnyASN1Element(&raw, &tag) || !encoded.Empty() {
		return decodedDistributionPointName{}, fmt.Errorf(
			"invalid DistributionPointName in DistributionPoint %d",
			index,
		)
	}
	element := cryptobyte.String(raw)
	var value cryptobyte.String
	var parsedTag cryptobyte_asn1.Tag
	if !element.ReadAnyASN1(&value, &parsedTag) || !element.Empty() || parsedTag != tag {
		return decodedDistributionPointName{}, fmt.Errorf(
			"invalid DistributionPointName in DistributionPoint %d",
			index,
		)
	}

	switch tag {
	case cryptobyte_asn1.Tag(0).ContextSpecific().Constructed():
		if value.Empty() {
			return decodedDistributionPointName{}, fmt.Errorf("empty fullName in DistributionPoint %d", index)
		}
		names, err := readGeneralNames(&value)
		if err != nil {
			return decodedDistributionPointName{}, fmt.Errorf(
				"invalid fullName in DistributionPoint %d: %w",
				index,
				err,
			)
		}
		return decodedDistributionPointName{
			Kind:         decodedFullName,
			GeneralNames: names,
		}, nil

	case cryptobyte_asn1.Tag(1).ContextSpecific().Constructed():
		if value.Empty() {
			return decodedDistributionPointName{}, fmt.Errorf(
				"empty nameRelativeToCRLIssuer in DistributionPoint %d",
				index,
			)
		}
		_, nameDER, err := encodeRelativeDistinguishedName(value)
		if err != nil {
			return decodedDistributionPointName{}, fmt.Errorf(
				"invalid nameRelativeToCRLIssuer in DistributionPoint %d: %w",
				index,
				err,
			)
		}
		parsed, err := internalasn1.ParseDistinguishedNameStrict(nameDER)
		if err != nil || len(parsed.RDNs) != 1 {
			return decodedDistributionPointName{}, fmt.Errorf(
				"invalid nameRelativeToCRLIssuer in DistributionPoint %d",
				index,
			)
		}
		return decodedDistributionPointName{
			Kind:         decodedNameRelativeToCRLIssuer,
			RelativeName: append([]byte(nil), value...),
			RelativeRaw:  append([]byte(nil), raw...),
		}, nil

	default:
		return decodedDistributionPointName{}, fmt.Errorf(
			"unknown DistributionPointName in DistributionPoint %d",
			index,
		)
	}
}

func encodeRelativeDistinguishedName(contents []byte) (rdnDER, nameDER []byte, err error) {
	var rdnBuilder cryptobyte.Builder
	rdnBuilder.AddASN1(cryptobyte_asn1.SET, func(builder *cryptobyte.Builder) {
		builder.AddBytes(contents)
	})
	rdnDER, err = rdnBuilder.Bytes()
	if err != nil {
		return nil, nil, err
	}

	var nameBuilder cryptobyte.Builder
	nameBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddBytes(rdnDER)
	})
	nameDER, err = nameBuilder.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return rdnDER, nameDER, nil
}

func projectCRLDistributionPoints(decoded []decodedCRLDistributionPoint) *node.Node {
	n := node.New("cRLDistributionPoints", nil)
	distributionPointsNode := node.New("distributionPoints", nil)
	n.Children["distributionPoints"] = distributionPointsNode
	n.Children["empty"] = node.New("empty", false)

	for index, distributionPoint := range decoded {
		key := strconv.Itoa(index)
		distributionPointsNode.Children[key] = projectCRLDistributionPoint(key, distributionPoint)
	}
	n.Children["count"] = node.New("count", len(decoded))
	return n
}

func projectCRLDistributionPoint(name string, decoded decodedCRLDistributionPoint) *node.Node {
	n := node.New(name, nil)
	if decoded.Name != nil {
		n.Children["distributionPoint"] = projectDistributionPointName(*decoded.Name)
	}
	if decoded.Reasons != nil {
		n.Children["reasons"] = projectReasonFlags(*decoded.Reasons)
	}
	if decoded.CRLIssuer != nil {
		issuerNode := node.New("cRLIssuer", nil)
		issuerNode.Children["present"] = node.New("present", true)
		addParsedGeneralNames(issuerNode, decoded.CRLIssuer)
		issuerNode.Children["count"] = node.New("count", len(decoded.CRLIssuer))
		n.Children["cRLIssuer"] = issuerNode
	}

	hasFullName := decoded.Name != nil && decoded.Name.Kind == decodedFullName
	n.Children["hasFullName"] = node.New("hasFullName", hasFullName)
	n.Children["hasReasons"] = node.New("hasReasons", decoded.Reasons != nil)
	n.Children["hasCRLIssuer"] = node.New("hasCRLIssuer", decoded.CRLIssuer != nil)
	return n
}

func projectDistributionPointName(decoded decodedDistributionPointName) *node.Node {
	n := node.New("distributionPoint", nil)
	switch decoded.Kind {
	case decodedFullName:
		fullNameNode := node.New("fullName", nil)
		generalNamesNode := node.New("generalNames", nil)
		addParsedGeneralNames(generalNamesNode, decoded.GeneralNames)
		fullNameNode.Children["generalNames"] = generalNamesNode
		fullNameNode.Children["count"] = node.New("count", len(decoded.GeneralNames))
		n.Children["fullName"] = fullNameNode

	case decodedNameRelativeToCRLIssuer:
		rdnDER, nameDER, err := encodeRelativeDistinguishedName(decoded.RelativeName)
		if err != nil {
			break
		}
		relativeName := nameprojector.BuildRawName("nameRelativeToCRLIssuer", nameDER)
		relativeName.Children["raw"] = node.New("raw", append([]byte(nil), rdnDER...))
		relativeName.Children["rawValue"] = node.New(
			"rawValue",
			append([]byte(nil), decoded.RelativeName...),
		)
		relativeName.Children["encoded"] = node.New(
			"encoded",
			append([]byte(nil), decoded.RelativeRaw...),
		)
		n.Children["nameRelativeToCRLIssuer"] = relativeName
	}
	return n
}
