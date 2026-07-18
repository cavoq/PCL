package zcrypto

import (
	"fmt"
	"strconv"

	"github.com/cavoq/PCL/internal/node"
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
}

type decodedCRLDistributionPoint struct {
	Name      *decodedDistributionPointName
	Reasons   *decodedReasonFlags
	CRLIssuer []parsedGeneralName
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
	var value cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !encoded.ReadAnyASN1(&value, &tag) || !encoded.Empty() {
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
		return decodedDistributionPointName{
			Kind:         decodedNameRelativeToCRLIssuer,
			RelativeName: append([]byte(nil), value...),
		}, nil

	default:
		return decodedDistributionPointName{}, fmt.Errorf(
			"unknown DistributionPointName in DistributionPoint %d",
			index,
		)
	}
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
		n.Children["nameRelativeToCRLIssuer"] = node.New(
			"nameRelativeToCRLIssuer",
			decoded.RelativeName,
		)
	}
	return n
}
