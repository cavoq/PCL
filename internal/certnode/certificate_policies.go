package certnode

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

// ParseCertPoliciesStrict decodes, validates, and projects exactly one
// CertificatePolicies value as defined by RFC 5280 section 4.2.1.4.
func ParseCertPoliciesStrict(extValue []byte) (*node.Node, error) {
	policies, err := x509ext.DecodeCertificatePolicies(extValue)
	if err != nil {
		return nil, err
	}
	return buildCertificatePoliciesNode(policies), nil
}
