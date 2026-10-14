package zcrypto

import "github.com/cavoq/PCL/internal/node"

// ParseCertPoliciesStrict decodes, validates, and projects exactly one
// CertificatePolicies value as defined by RFC 5280 section 4.2.1.4.
func ParseCertPoliciesStrict(extValue []byte) (*node.Node, error) {
	policies, err := decodeCertificatePolicies(extValue)
	if err != nil {
		return nil, err
	}
	return buildCertificatePoliciesNode(policies), nil
}

// DecodeCertificatePolicyIdentifiersStrict returns the encoded policy OIDs
// only after the complete CertificatePolicies value, including qualifiers,
// has passed strict decoding.
func DecodeCertificatePolicyIdentifiersStrict(extValue []byte) ([]string, error) {
	policies, err := decodeCertificatePolicies(extValue)
	if err != nil {
		return nil, err
	}
	identifiers := make([]string, 0, len(policies.Policies))
	for _, policy := range policies.Policies {
		identifiers = append(identifiers, policy.OID)
	}
	return identifiers, nil
}
