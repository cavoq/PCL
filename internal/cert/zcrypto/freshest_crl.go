package zcrypto

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

// ParseFreshestCRLStrict uses the same wire decoder as CRL Distribution
// Points while retaining the established certificate extension node schema.
func ParseFreshestCRLStrict(extValue []byte) (*node.Node, error) {
	decoded, err := x509ext.DecodeDistributionPoints(extValue)
	if err != nil {
		return nil, err
	}
	n := projectCRLDistributionPoints(decoded)
	n.Name = "freshestCRL"
	return n, nil
}

func DecodeFreshestCRLStrict(extValue []byte) ([]x509ext.DistributionPoint, error) {
	return x509ext.DecodeDistributionPoints(extValue)
}
