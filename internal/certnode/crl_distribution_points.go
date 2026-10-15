package certnode

import (
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ParseCRLDPStrict parses exactly one CRLDistributionPoints value.
func ParseCRLDPStrict(extValue []byte) (*node.Node, error) {
	distributionPoints, err := x509ext.DecodeDistributionPoints(extValue)
	if err != nil {
		return nil, err
	}
	return projectCRLDistributionPoints(distributionPoints), nil
}

func projectCRLDistributionPoints(decoded []x509ext.DistributionPoint) *node.Node {
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

func projectCRLDistributionPoint(name string, decoded x509ext.DistributionPoint) *node.Node {
	n := node.New(name, nil)
	if decoded.Name != nil {
		n.Children["distributionPoint"] = projectDistributionPointName(*decoded.Name)
	}
	if decoded.Reasons != nil {
		n.Children["reasons"] = x509node.BuildReasonFlags("reasons", decoded.Reasons)
	}
	if decoded.CRLIssuer != nil {
		issuerNode := node.New("cRLIssuer", nil)
		issuerNode.Children["present"] = node.New("present", true)
		x509node.AddGeneralNames(issuerNode, decoded.CRLIssuer)
		issuerNode.Children["count"] = node.New("count", len(decoded.CRLIssuer))
		n.Children["cRLIssuer"] = issuerNode
	}

	hasFullName := decoded.Name != nil && decoded.Name.Kind == x509ext.DistributionPointNameFullName
	n.Children["hasFullName"] = node.New("hasFullName", hasFullName)
	n.Children["hasReasons"] = node.New("hasReasons", decoded.Reasons != nil)
	n.Children["hasCRLIssuer"] = node.New("hasCRLIssuer", decoded.CRLIssuer != nil)
	return n
}

func projectDistributionPointName(decoded x509ext.DistributionPointName) *node.Node {
	n := node.New("distributionPoint", nil)
	switch decoded.Kind {
	case x509ext.DistributionPointNameFullName:
		fullNameNode := node.New("fullName", nil)
		generalNamesNode := node.New("generalNames", nil)
		x509node.AddGeneralNames(generalNamesNode, decoded.FullName)
		fullNameNode.Children["generalNames"] = generalNamesNode
		fullNameNode.Children["count"] = node.New("count", len(decoded.FullName))
		n.Children["fullName"] = fullNameNode

	case x509ext.DistributionPointNameRelative:
		rdn := cryptobyte.String(decoded.RelativeRDN)
		var contents cryptobyte.String
		if !rdn.ReadASN1(&contents, cryptobyte_asn1.SET) || !rdn.Empty() {
			break
		}
		relativeName := x509node.BuildRawName("nameRelativeToCRLIssuer", decoded.RelativeNameDER)
		relativeName.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RelativeRDN...))
		relativeName.Children["rawValue"] = node.New("rawValue", append([]byte(nil), contents...))
		relativeName.Children["encoded"] = node.New(
			"encoded",
			append([]byte(nil), decoded.RawDER...),
		)
		n.Children["nameRelativeToCRLIssuer"] = relativeName
	}
	return n
}
