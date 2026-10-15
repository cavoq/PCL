package x509ext

// DecodeCertificatePolicyIdentifiersStrict returns the encoded policy OIDs
// only after the complete CertificatePolicies value, including qualifiers,
// has passed strict decoding.
func DecodeCertificatePolicyIdentifiersStrict(extValue []byte) ([]string, error) {
	policies, err := DecodeCertificatePolicies(extValue)
	if err != nil {
		return nil, err
	}
	identifiers := make([]string, 0, len(policies.Policies))
	for _, policy := range policies.Policies {
		identifiers = append(identifiers, policy.OID)
	}
	return identifiers, nil
}
