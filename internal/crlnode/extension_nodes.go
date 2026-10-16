package crlnode

import (
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
	"github.com/zmap/zcrypto/x509/pkix"
)

func projectCRLExtension(extension pkix.Extension) (*node.Node, error) {
	switch extension.Id.String() {
	case oid.AuthorityKeyIdentifier:
		facts, err := x509ext.DecodeAuthorityKeyIdentifierExtension(extension)
		if err != nil {
			return nil, err
		}
		return x509node.ProjectAuthorityKeyIdentifier(facts), nil
	case oid.CRLNumber:
		facts, err := x509ext.DecodeIntegerExtension(extension)
		if err != nil {
			return nil, err
		}
		return projectIntegerExtension("cRLNumber", facts), nil
	case oid.DeltaCRLIndicator:
		facts, err := x509ext.DecodeIntegerExtension(extension)
		if err != nil {
			return nil, err
		}
		return projectIntegerExtension("deltaCRLIndicator", facts), nil
	case oid.IssuingDistributionPoint:
		facts, err := x509ext.DecodeIssuingDistributionPointExtension(extension)
		if err != nil {
			return nil, err
		}
		return projectIssuingDistributionPoint(facts), nil
	case oid.FreshestCRL:
		facts, err := x509ext.DecodeDistributionPointsExtension(extension)
		if err != nil {
			return nil, err
		}
		return projectDistributionPoints("freshestCRL", facts.RawDER, facts.Points), nil
	default:
		return nil, nil
	}
}

func projectEntryExtension(extension pkix.Extension) (*node.Node, error) {
	switch extension.Id.String() {
	case oid.CRLReason:
		facts, err := x509ext.DecodeReasonCodeExtension(extension)
		if err != nil {
			return nil, err
		}
		n := node.New("cRLReason", int(facts.Value))
		n.Children["raw"] = node.New("raw", append([]byte(nil), facts.RawDER...))
		n.Children["value"] = node.New("value", int(facts.Value))
		return n, nil
	case oid.InvalidityDate:
		facts, err := x509ext.DecodeInvalidityDateExtension(extension)
		if err != nil {
			return nil, err
		}
		n := node.New("invalidityDate", facts.Value)
		n.Children["raw"] = node.New("raw", append([]byte(nil), facts.RawDER...))
		n.Children["value"] = node.New("value", facts.Value)
		n.Children["rawValue"] = node.New("rawValue", facts.Encoding.RawValue)
		n.Children["encoding"] = node.New("encoding", facts.Encoding.Tag)
		n.Children["hasSeconds"] = node.New("hasSeconds", facts.Encoding.HasSeconds)
		n.Children["hasFraction"] = node.New("hasFraction", facts.Encoding.HasFraction)
		n.Children["hasZulu"] = node.New("hasZulu", facts.Encoding.HasZulu)
		return n, nil
	case oid.CertificateIssuer:
		facts, err := x509ext.DecodeCertificateIssuerExtension(extension)
		if err != nil {
			return nil, err
		}
		n := node.New("certificateIssuer", len(facts.Names))
		n.Children["raw"] = node.New("raw", append([]byte(nil), facts.RawDER...))
		entries := node.New("entries", nil)
		x509node.AddGeneralNames(entries, facts.Names)
		n.Children["entries"] = entries
		n.Children["count"] = node.New("count", len(facts.Names))
		return n, nil
	default:
		return nil, nil
	}
}

func projectIntegerExtension(name string, facts *x509ext.IntegerExtensionFacts) *node.Node {
	n := node.New(name, facts.Value.Scalar())
	n.Children["raw"] = node.New("raw", append([]byte(nil), facts.RawDER...))
	n.Children["value"] = node.New("value", facts.Value.Scalar())
	n.Children["decimal"] = node.New("decimal", facts.Value.Decimal)
	n.Children["fitsInt"] = node.New("fitsInt", facts.Value.FitsInt)
	n.Children["contentLength"] = node.New("contentLength", len(facts.Value.Content))
	return n
}

func projectIssuingDistributionPoint(facts *x509ext.IssuingDistributionPointFacts) *node.Node {
	n := node.New("issuingDistributionPoint", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), facts.RawDER...))
	if facts.DistributionPoint != nil {
		n.Children["distributionPoint"] = projectDistributionPointName(facts.DistributionPoint)
	}
	n.Children["onlyContainsUserCerts"] = node.New("onlyContainsUserCerts", facts.OnlyContainsUserCerts)
	n.Children["onlyContainsCACerts"] = node.New("onlyContainsCACerts", facts.OnlyContainsCACerts)
	n.Children["indirectCRL"] = node.New("indirectCRL", facts.IndirectCRL)
	n.Children["onlyContainsAttributeCerts"] = node.New(
		"onlyContainsAttributeCerts",
		facts.OnlyContainsAttributeCerts,
	)
	if facts.OnlySomeReasons != nil {
		n.Children["onlySomeReasons"] = x509node.BuildReasonFlags("onlySomeReasons", facts.OnlySomeReasons)
	}
	return n
}

func projectDistributionPoints(name string, raw []byte, points []x509ext.DistributionPoint) *node.Node {
	n := node.New(name, nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), raw...))
	n.Children["count"] = node.New("count", len(points))
	n.Children["empty"] = node.New("empty", false)
	collection := node.New("distributionPoints", nil)
	n.Children["distributionPoints"] = collection
	for index, point := range points {
		key := strconv.Itoa(index)
		pointNode := node.New(key, nil)
		pointNode.Children["raw"] = node.New("raw", append([]byte(nil), point.RawDER...))
		if point.Name != nil {
			pointNode.Children["distributionPoint"] = projectDistributionPointName(point.Name)
		}
		if point.Reasons != nil {
			pointNode.Children["reasons"] = x509node.BuildReasonFlags("reasons", point.Reasons)
		}
		if point.CRLIssuer != nil {
			issuer := node.New("cRLIssuer", nil)
			x509node.AddGeneralNames(issuer, point.CRLIssuer)
			issuer.Children["count"] = node.New("count", len(point.CRLIssuer))
			pointNode.Children["cRLIssuer"] = issuer
		}
		collection.Children[key] = pointNode
	}
	return n
}

func projectDistributionPointName(name *x509ext.DistributionPointName) *node.Node {
	n := node.New("distributionPoint", nil)
	if name == nil {
		return n
	}
	switch name.Kind {
	case x509ext.DistributionPointNameFullName:
		fullName := node.New("fullName", nil)
		generalNames := node.New("generalNames", nil)
		x509node.AddGeneralNames(generalNames, name.FullName)
		fullName.Children["generalNames"] = generalNames
		fullName.Children["count"] = node.New("count", len(name.FullName))
		n.Children["fullName"] = fullName
	case x509ext.DistributionPointNameRelative:
		relative := x509node.BuildRawName("nameRelativeToCRLIssuer", name.RelativeNameDER)
		relative.Children["raw"] = node.New("raw", append([]byte(nil), name.RelativeRDN...))
		relative.Children["encoded"] = node.New("encoded", append([]byte(nil), name.RawDER...))
		n.Children["nameRelativeToCRLIssuer"] = relative
	}
	return n
}
