package certnode

import (
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

// ParseKeyUsageStrict parses exactly one RFC 5280 KeyUsage BIT STRING.
func ParseKeyUsageStrict(extValue []byte) (*node.Node, error) {
	decoded, err := x509ext.DecodeKeyUsage(extValue)
	if err != nil {
		return nil, err
	}
	return projectKeyUsage(decoded), nil
}

func projectKeyUsage(decoded x509ext.KeyUsage) *node.Node {
	n := node.New("keyUsage", decoded.Value)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["rawValue"] = node.New("rawValue", append([]byte(nil), decoded.RawValue...))
	n.Children["bitLength"] = node.New("bitLength", decoded.BitLength)
	n.Children["unusedBits"] = node.New("unusedBits", decoded.UnusedBits)

	definitions := []struct {
		bit  int
		name string
	}{
		{0, "digitalSignature"},
		{1, "contentCommitment"},
		{2, "keyEncipherment"},
		{3, "dataEncipherment"},
		{4, "keyAgreement"},
		{5, "keyCertSign"},
		{6, "cRLSign"},
		{7, "encipherOnly"},
		{8, "decipherOnly"},
	}
	for _, definition := range definitions {
		set := decoded.Value&(1<<definition.bit) != 0
		n.Children[definition.name] = node.New(definition.name, set)
	}
	// nonRepudiation is the original RFC 5280 spelling and remains an alias
	// of the later X.509 name contentCommitment.
	n.Children["nonRepudiation"] = node.New(
		"nonRepudiation",
		decoded.Value&(1<<1) != 0,
	)
	return n
}

// ParseBasicConstraintsStrict parses exactly one BasicConstraints sequence,
// preserving whether its DEFAULT and OPTIONAL fields were encoded.
func ParseBasicConstraintsStrict(extValue []byte) (*node.Node, error) {
	decoded, err := x509ext.DecodeBasicConstraints(extValue)
	if err != nil {
		return nil, err
	}
	return projectBasicConstraints(decoded), nil
}

func projectBasicConstraints(decoded x509ext.BasicConstraints) *node.Node {
	n := node.New("basicConstraints", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["cA"] = node.New("cA", decoded.CA)
	n.Children["cAPresent"] = node.New("cAPresent", decoded.CAPresent)
	n.Children["pathLenConstraintPresent"] = node.New(
		"pathLenConstraintPresent",
		decoded.PathLenConstraintPresent,
	)
	if decoded.PathLenConstraintPresent {
		pathLen := node.New(
			"pathLenConstraint",
			decoded.PathLenConstraint.Scalar(),
		)
		pathLen.Children["decimal"] = node.New("decimal", decoded.PathLenConstraint.Decimal)
		pathLen.Children["fitsInt"] = node.New("fitsInt", decoded.PathLenConstraint.FitsInt)
		n.Children["pathLenConstraint"] = pathLen
	}
	return n
}

// ParseExtKeyUsageStrict projects every KeyPurposeId, including anyExtendedKeyUsage
// and identifiers unknown to the underlying x509 library.
func ParseExtKeyUsageStrict(extValue []byte) (*node.Node, error) {
	decoded, err := x509ext.DecodeExtendedKeyUsage(extValue)
	if err != nil {
		return nil, err
	}
	return projectExtendedKeyUsage(decoded), nil
}

func projectExtendedKeyUsage(decoded x509ext.ExtendedKeyUsage) *node.Node {
	n := node.New("extKeyUsage", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), decoded.RawDER...))
	n.Children["count"] = node.New("count", len(decoded.Usages))
	usages := node.New("usages", nil)
	unknown := node.New("unknown", nil)
	n.Children["usages"] = usages

	unknownCount := 0
	for index, decodedUsage := range decoded.Usages {
		key := strconv.Itoa(index)
		usage := node.New(key, decodedUsage.OID)
		usage.Children["oid"] = node.New("oid", decodedUsage.OID)
		usage.Children["raw"] = node.New("raw", append([]byte(nil), decodedUsage.RawDER...))
		if friendlyName, known := x509ext.ExtendedKeyUsageName(decodedUsage.OID); known {
			usage.Children["name"] = node.New("name", friendlyName)
			n.Children[friendlyName] = node.New(friendlyName, true)
		} else {
			unknownKey := strconv.Itoa(unknownCount)
			unknown.Children[unknownKey] = &node.Node{
				Name:     unknownKey,
				Value:    usage.Value,
				Children: usage.Children,
			}
			unknownCount++
		}
		usages.Children[key] = usage
		n.Children[decodedUsage.OID] = usage
	}
	if unknownCount > 0 {
		unknown.Children["count"] = node.New("count", unknownCount)
		n.Children["unknown"] = unknown
	}
	return n
}
