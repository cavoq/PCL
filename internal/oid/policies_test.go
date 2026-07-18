package oid

import "testing"

func TestCertificatePolicyName(t *testing.T) {
	tests := map[string]string{
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
	for policyOID, want := range tests {
		got, ok := CertificatePolicyName(policyOID)
		if !ok || got != want {
			t.Errorf("CertificatePolicyName(%q) = %q, want %q", policyOID, got, want)
		}
	}
	if got, ok := CertificatePolicyName("1.2.3.4"); ok || got != "" {
		t.Errorf("CertificatePolicyName(unknown) = %q, %v; want empty, false", got, ok)
	}
}
