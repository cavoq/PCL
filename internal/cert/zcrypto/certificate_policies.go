package zcrypto

import "github.com/cavoq/PCL/internal/node"

// ParseCertPolicies parses the Certificate Policies extension (OID 2.5.29.32)
// and returns a node tree with policyInformations and policyQualifiers.
// It is retained as a compatibility wrapper; callers which need to distinguish
// malformed DER should use ParseCertPoliciesStrict.
func ParseCertPolicies(extValue []byte) *node.Node {
	parsed, err := ParseCertPoliciesStrict(extValue)
	if err == nil {
		return parsed
	}
	return malformedExtensionNode("certificatePolicies", isEmptySequence(extValue))
}

// ParseCertPoliciesStrict decodes, validates, and projects exactly one
// CertificatePolicies value as defined by RFC 5280 section 4.2.1.4.
func ParseCertPoliciesStrict(extValue []byte) (*node.Node, error) {
	policies, err := decodeCertificatePolicies(extValue)
	if err != nil {
		return nil, err
	}
	return buildCertificatePoliciesNode(policies), nil
}
