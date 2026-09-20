package zcrypto

import (
	"fmt"
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
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
	Reasons   *x509ext.ReasonFlags
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
	ReasonMask                x509ext.ReasonMask
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
			pointFacts.ReasonMask = distributionPoint.Reasons.Mask
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
	shared, err := x509ext.DecodeDistributionPoints(extValue)
	if err != nil {
		return nil, err
	}
	decoded := make([]decodedCRLDistributionPoint, 0, len(shared))
	for _, point := range shared {
		converted := decodedCRLDistributionPoint{
			CRLIssuer: append([]parsedGeneralName(nil), point.CRLIssuer...),
		}
		if point.Name != nil {
			name := decodedDistributionPointName{
				GeneralNames: append([]parsedGeneralName(nil), point.Name.FullName...),
				RelativeRaw:  append([]byte(nil), point.Name.RawDER...),
			}
			switch point.Name.Kind {
			case x509ext.DistributionPointNameFullName:
				name.Kind = decodedFullName
			case x509ext.DistributionPointNameRelative:
				name.Kind = decodedNameRelativeToCRLIssuer
				rdn := cryptobyte.String(point.Name.RelativeRDN)
				var contents cryptobyte.String
				if !rdn.ReadASN1(&contents, cryptobyte_asn1.SET) || !rdn.Empty() {
					return nil, fmt.Errorf("invalid shared relative distinguished name")
				}
				name.RelativeName = append([]byte(nil), contents...)
			default:
				return nil, fmt.Errorf("unknown shared DistributionPointName kind")
			}
			converted.Name = &name
		}
		if point.Reasons != nil {
			converted.Reasons = point.Reasons
		}
		decoded = append(decoded, converted)
	}
	return decoded, nil
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
		n.Children["reasons"] = projectReasonFlags(decoded.Reasons)
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
