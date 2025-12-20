package policy

import "encoding/asn1"

type Extension struct {
	OID  asn1.ObjectIdentifier
	Name string
}

var (
	ExtSubjectDirectoryAttributes = Extension{asn1.ObjectIdentifier{2, 5, 29, 9}, "Subject Directory Attributes"}
	ExtSubjectKeyIdentifier       = Extension{asn1.ObjectIdentifier{2, 5, 29, 14}, "Subject Key Identifier"}
	ExtKeyUsage                   = Extension{asn1.ObjectIdentifier{2, 5, 29, 15}, "Key Usage"}
	ExtPrivateKeyUsagePeriod      = Extension{asn1.ObjectIdentifier{2, 5, 29, 16}, "Private Key Usage Period"}
	ExtSubjectAltName             = Extension{asn1.ObjectIdentifier{2, 5, 29, 17}, "Subject Alternative Name"}
	ExtIssuerAltName              = Extension{asn1.ObjectIdentifier{2, 5, 29, 18}, "Issuer Alternative Name"}
	ExtBasicConstraints           = Extension{asn1.ObjectIdentifier{2, 5, 29, 19}, "Basic Constraints"}
	ExtNameConstraints            = Extension{asn1.ObjectIdentifier{2, 5, 29, 30}, "Name Constraints"}
	ExtCRLDistributionPoints      = Extension{asn1.ObjectIdentifier{2, 5, 29, 31}, "CRL Distribution Points"}
	ExtCertificatePolicies        = Extension{asn1.ObjectIdentifier{2, 5, 29, 32}, "Certificate Policies"}
	ExtPolicyMappings             = Extension{asn1.ObjectIdentifier{2, 5, 29, 33}, "Policy Mappings"}
	ExtAuthorityKeyIdentifier     = Extension{asn1.ObjectIdentifier{2, 5, 29, 35}, "Authority Key Identifier"}
	ExtPolicyConstraints          = Extension{asn1.ObjectIdentifier{2, 5, 29, 36}, "Policy Constraints"}
	ExtExtendedKeyUsage           = Extension{asn1.ObjectIdentifier{2, 5, 29, 37}, "Extended Key Usage"}
	ExtFreshestCRL                = Extension{asn1.ObjectIdentifier{2, 5, 29, 46}, "Freshest CRL"}
	ExtInhibitAnyPolicy           = Extension{asn1.ObjectIdentifier{2, 5, 29, 54}, "Inhibit anyPolicy"}
	ExtAuthorityInfoAccess        = Extension{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, "Authority Information Access"}
	ExtSubjectInfoAccess          = Extension{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}, "Subject Information Access"}
)

var KnownExtensions = []Extension{
	ExtSubjectDirectoryAttributes,
	ExtSubjectKeyIdentifier,
	ExtKeyUsage,
	ExtPrivateKeyUsagePeriod,
	ExtSubjectAltName,
	ExtIssuerAltName,
	ExtBasicConstraints,
	ExtNameConstraints,
	ExtCRLDistributionPoints,
	ExtCertificatePolicies,
	ExtPolicyMappings,
	ExtAuthorityKeyIdentifier,
	ExtPolicyConstraints,
	ExtExtendedKeyUsage,
	ExtFreshestCRL,
	ExtInhibitAnyPolicy,
	ExtAuthorityInfoAccess,
	ExtSubjectInfoAccess,
}

func IsKnownExtension(oid asn1.ObjectIdentifier) bool {
	for _, ext := range KnownExtensions {
		if ext.OID.Equal(oid) {
			return true
		}
	}
	return false
}

func GetExtensionName(oid asn1.ObjectIdentifier) string {
	for _, ext := range KnownExtensions {
		if ext.OID.Equal(oid) {
			return ext.Name
		}
	}
	return ""
}
