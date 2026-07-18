package oid

const (
	// Certificate policy qualifier OIDs (RFC 5280).
	PolicyQualifierCPS        = "1.3.6.1.5.5.7.2.1"
	PolicyQualifierUserNotice = "1.3.6.1.5.5.7.2.2"

	// Certificate policy OIDs.
	AnyPolicy = "2.5.29.32.0"

	CABFExtendedValidationPolicy    = "2.23.140.1.1"
	CABFDomainValidatedPolicy       = "2.23.140.1.2.1"
	CABFOrganizationValidatedPolicy = "2.23.140.1.2.2"
	CABFIndividualValidatedPolicy   = "2.23.140.1.2.3"
	CABFCodeSigningPolicy           = "2.23.140.1.4.1"

	CABFSMIMEMailboxLegacyPolicy       = "2.23.140.1.5.1.1"
	CABFSMIMEMailboxMultipurposePolicy = "2.23.140.1.5.1.2"
	CABFSMIMEMailboxStrictPolicy       = "2.23.140.1.5.1.3"
	CABFSMIMEOrgLegacyPolicy           = "2.23.140.1.5.2.1"
	CABFSMIMEOrgMultipurposePolicy     = "2.23.140.1.5.2.2"
	CABFSMIMEOrgStrictPolicy           = "2.23.140.1.5.2.3"
	CABFSMIMESponsorLegacyPolicy       = "2.23.140.1.5.3.1"
	CABFSMIMESponsorMultipurposePolicy = "2.23.140.1.5.3.2"
	CABFSMIMESponsorStrictPolicy       = "2.23.140.1.5.3.3"
)

var certificatePolicyNames = map[string]string{
	AnyPolicy:                          "anyPolicy",
	CABFExtendedValidationPolicy:       "evPolicy",
	CABFDomainValidatedPolicy:          "dvPolicy",
	CABFOrganizationValidatedPolicy:    "ovPolicy",
	CABFIndividualValidatedPolicy:      "ivPolicy",
	CABFCodeSigningPolicy:              "codeSigningPolicy",
	CABFSMIMEMailboxLegacyPolicy:       "smimeMailboxLegacy",
	CABFSMIMEMailboxMultipurposePolicy: "smimeMailboxMultipurpose",
	CABFSMIMEMailboxStrictPolicy:       "smimeMailboxStrict",
	CABFSMIMEOrgLegacyPolicy:           "smimeOrgLegacy",
	CABFSMIMEOrgMultipurposePolicy:     "smimeOrgMultipurpose",
	CABFSMIMEOrgStrictPolicy:           "smimeOrgStrict",
	CABFSMIMESponsorLegacyPolicy:       "smimeSponsorLegacy",
	CABFSMIMESponsorMultipurposePolicy: "smimeSponsorMultipurpose",
	CABFSMIMESponsorStrictPolicy:       "smimeSponsorStrict",
}

// CertificatePolicyName returns the stable node name for a known certificate
// policy OID.
func CertificatePolicyName(policyOID string) (string, bool) {
	name, ok := certificatePolicyNames[policyOID]
	return name, ok
}
