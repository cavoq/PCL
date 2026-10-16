package certnode

import (
	"net"
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
)

// ParseNameConstraintsStrict parses all GeneralName alternatives and retains
// exact GeneralSubtree and GeneralName DER. Presence of minimum and maximum is
// represented separately from their integer values.
func ParseNameConstraintsStrict(extValue []byte) (*node.Node, error) {
	decoded, err := x509ext.DecodeNameConstraints(extValue)
	if err != nil {
		return nil, err
	}
	return projectNameConstraints(decoded), nil
}

func projectNameConstraints(decoded x509ext.NameConstraints) *node.Node {
	n := node.New("nameConstraints", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	if len(decoded.Permitted) > 0 {
		n.Children["permittedSubtrees"] = projectGeneralSubtrees(
			"permittedSubtrees",
			decoded.Permitted,
		)
	}
	if len(decoded.Excluded) > 0 {
		n.Children["excludedSubtrees"] = projectGeneralSubtrees(
			"excludedSubtrees",
			decoded.Excluded,
		)
	}
	return n
}

func projectGeneralSubtrees(name string, decoded []x509ext.GeneralSubtree) *node.Node {
	n := node.New(name, nil)
	n.Children["count"] = node.New("count", len(decoded))
	typeCounts := make(map[int]int)
	for index, subtree := range decoded {
		key := strconv.Itoa(index)
		projected := projectGeneralSubtree(key, subtree)
		n.Children[key] = projected

		typeName := x509ext.GeneralNameType(subtree.Base.Tag)
		typeCollection := n.Children[typeName]
		if typeCollection == nil {
			typeCollection = node.New(typeName, nil)
			n.Children[typeName] = typeCollection
		}
		typeIndex := strconv.Itoa(typeCounts[subtree.Base.Tag])
		typeCollection.Children[typeIndex] = aliasGeneralNameNode(typeIndex, projected)
		typeCounts[subtree.Base.Tag]++
	}
	return n
}

func projectGeneralSubtree(name string, decoded x509ext.GeneralSubtree) *node.Node {
	base := buildNameConstraintGeneralName("base", decoded.Base)
	n := node.New(name, x509node.CloneScalar(base.Value))
	n.Children["base"] = base
	n.Children["value"] = node.New("value", x509node.CloneScalar(base.Value))
	n.Children["type"] = node.New("type", x509ext.GeneralNameType(decoded.Base.Tag))
	n.Children["tag"] = node.New("tag", decoded.Base.Tag)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["minimum"] = integerFactNode(
		"minimum",
		decoded.Minimum,
		decoded.MinimumPresent,
		decoded.MinimumRaw,
	)
	n.Children["minimumPresent"] = node.New("minimumPresent", decoded.MinimumPresent)
	n.Children["maximumPresent"] = node.New("maximumPresent", decoded.MaximumPresent)
	if decoded.MinimumPresent {
		n.Children["min"] = integerFactNode("min", decoded.Minimum, true, decoded.MinimumRaw)
	}
	if decoded.MaximumPresent {
		n.Children["maximum"] = integerFactNode(
			"maximum",
			decoded.Maximum,
			true,
			decoded.MaximumRaw,
		)
		n.Children["max"] = integerFactNode("max", decoded.Maximum, true, decoded.MaximumRaw)
	}
	return n
}

func integerFactNode(
	name string,
	value x509ext.NonNegativeInteger,
	present bool,
	raw []byte,
) *node.Node {
	var scalar any = 0
	if present {
		scalar = value.Scalar()
	}
	n := node.New(name, scalar)
	n.Children["present"] = node.New("present", present)
	if present {
		n.Children["raw"] = node.New("raw", append([]byte(nil), raw...))
		n.Children["decimal"] = node.New("decimal", value.Decimal)
		n.Children["fitsInt"] = node.New("fitsInt", value.FitsInt)
	}
	return n
}

func buildNameConstraintGeneralName(name string, parsed x509ext.GeneralName) *node.Node {
	n := x509node.BuildGeneralName(name, parsed)
	if parsed.Tag != 7 {
		return n
	}

	half := len(parsed.RawValue) / 2
	addressBytes := append([]byte(nil), parsed.RawValue[:half]...)
	maskBytes := append([]byte(nil), parsed.RawValue[half:]...)
	address := net.IP(addressBytes)
	mask := net.IPMask(maskBytes)
	network := (&net.IPNet{IP: address, Mask: mask}).String()
	n.Value = network
	n.Children["value"] = node.New("value", network)
	n.Children["address"] = node.New("address", address.String())
	n.Children["mask"] = node.New("mask", append([]byte(nil), maskBytes...))
	if prefixLength, bits := mask.Size(); bits != 0 {
		n.Children["prefixLength"] = node.New("prefixLength", prefixLength)
	}
	return n
}
