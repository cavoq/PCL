package policy

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

type PolicyChain struct {
	Name     string
	Policies []*Policy
}

type Policy struct {
	Name        string           `yaml:"name" json:"name" jsonschema:"required,description=Policy name"`
	CertOrder   *int             `yaml:"cert_order" json:"cert_order" jsonschema:"required,minimum=0,description=Position in certificate chain (0=leaf 1=intermediate 2+=root)"`
	Description string           `yaml:"description,omitempty" json:"description,omitempty" jsonschema:"description=Policy description"`
	BasicFields *BasicFieldsRule `yaml:"basic_fields,omitempty" json:"basic_fields,omitempty" jsonschema:"description=TBSCertificate field requirements"`
	Extensions  *Extensions      `yaml:"extensions,omitempty" json:"extensions,omitempty" jsonschema:"description=Certificate extension requirements"`
}

type ValidityRule struct {
	MinDays *int `yaml:"min_days,omitempty" json:"min_days,omitempty" jsonschema:"minimum=1,description=Minimum validity period in days"`
	MaxDays *int `yaml:"max_days,omitempty" json:"max_days,omitempty" jsonschema:"minimum=1,description=Maximum validity period in days"`
}

type BasicFieldsRule struct {
	RequireV3                      bool                      `yaml:"require_v3,omitempty" json:"require_v3,omitempty" jsonschema:"description=Require X.509 v3 certificates"`
	SerialNumber                   *SerialNumberRule         `yaml:"serial_number,omitempty" json:"serial_number,omitempty" jsonschema:"description=Serial number requirements"`
	SignatureAlgorithm             *SignatureAlgorithmRule   `yaml:"signatureAlgorithm,omitempty" json:"signatureAlgorithm,omitempty" jsonschema:"description=Signature algorithm constraints"`
	Issuer                         *NameRule                 `yaml:"issuer,omitempty" json:"issuer,omitempty" jsonschema:"description=Issuer name requirements"`
	Validity                       *ValidityRule             `yaml:"validity,omitempty" json:"validity,omitempty" jsonschema:"description=Validity period constraints"`
	Subject                        *NameRule                 `yaml:"subject,omitempty" json:"subject,omitempty" jsonschema:"description=Subject name requirements"`
	SubjectPublicKeyInfo           *SubjectPublicKeyInfoRule `yaml:"subjectPublicKeyInfo,omitempty" json:"subjectPublicKeyInfo,omitempty" jsonschema:"description=Public key algorithm constraints"`
	RejectUniqueIdentifiers        bool                      `yaml:"reject_unique_identifiers,omitempty" json:"reject_unique_identifiers,omitempty" jsonschema:"description=Reject certificates with unique identifiers"`
	RequireSignatureAlgorithmMatch bool                      `yaml:"require_signature_algorithm_match,omitempty" json:"require_signature_algorithm_match,omitempty" jsonschema:"description=Require TBSCertificate signature algorithm matches outer signature algorithm"`
	RequireCorrectTimeEncoding     bool                      `yaml:"require_correct_time_encoding,omitempty" json:"require_correct_time_encoding,omitempty" jsonschema:"description=Require correct UTCTime/GeneralizedTime encoding based on year"`
	RequireNonEmptyIssuer          bool                      `yaml:"require_non_empty_issuer,omitempty" json:"require_non_empty_issuer,omitempty" jsonschema:"description=Require non-empty issuer DN"`
	RequireEmptySubjectSANCritical bool                      `yaml:"require_empty_subject_san_critical,omitempty" json:"require_empty_subject_san_critical,omitempty" jsonschema:"description=Require critical SAN when subject DN is empty"`
}

type SerialNumberRule struct {
	RequirePositive bool `yaml:"require_positive,omitempty" json:"require_positive,omitempty" jsonschema:"description=Serial number must be a positive integer"`
	MaxLength       *int `yaml:"max_length,omitempty" json:"max_length,omitempty" jsonschema:"minimum=1,maximum=20,description=Maximum serial number length in octets"`
}

type NameRule struct {
	Allowed     []string `yaml:"allowed,omitempty" json:"allowed,omitempty" jsonschema:"description=Allowed name patterns (regex)"`
	Forbidden   []string `yaml:"forbidden,omitempty" json:"forbidden,omitempty" jsonschema:"description=Forbidden name patterns (regex)"`
	NoWildcards bool     `yaml:"no_wildcards,omitempty" json:"no_wildcards,omitempty" jsonschema:"description=Disallow wildcard certificates"`
}

type SubjectPublicKeyInfoRule struct {
	AllowedAlgorithms map[string]*KeyAlgorithmRule `yaml:"allowed_algorithms,omitempty" json:"allowed_algorithms,omitempty" jsonschema:"description=Allowed public key algorithms and constraints"`
}

type SignatureAlgorithmRule struct {
	AllowedAlgorithms []string `yaml:"allowed_algorithms,omitempty" json:"allowed_algorithms,omitempty" jsonschema:"description=Allowed signature algorithms"`
}

func (SignatureAlgorithmRule) JSONSchema() *jsonschema.Schema {
	props := jsonschema.NewProperties()
	props.Set("allowed_algorithms", &jsonschema.Schema{
		Type:        "array",
		Description: "Allowed signature algorithms",
		Items: &jsonschema.Schema{
			Type: "string",
			Enum: []any{
				"MD5-RSA",
				"SHA1-RSA",
				"SHA256-RSA",
				"SHA384-RSA",
				"SHA512-RSA",
				"SHA256-RSAPSS",
				"SHA384-RSAPSS",
				"SHA512-RSAPSS",
				"DSA-SHA1",
				"DSA-SHA256",
				"ECDSA-SHA1",
				"ECDSA-SHA256",
				"ECDSA-SHA384",
				"ECDSA-SHA512",
				"Ed25519",
			},
		},
	})
	return &jsonschema.Schema{
		Type:        "object",
		Description: "Signature algorithm constraints",
		Properties:  props,
	}
}

type KeyAlgorithmRule struct {
	MinSize       int      `yaml:"min_size,omitempty" json:"min_size,omitempty" jsonschema:"minimum=256,description=Minimum key size in bits"`
	AllowedCurves []string `yaml:"allowed_curves,omitempty" json:"allowed_curves,omitempty" jsonschema:"description=Allowed elliptic curves (EC only)"`
}

func (KeyAlgorithmRule) JSONSchema() *jsonschema.Schema {
	props := jsonschema.NewProperties()
	props.Set("min_size", &jsonschema.Schema{
		Type:        "integer",
		Minimum:     json.Number("256"),
		Description: "Minimum key size in bits",
	})
	props.Set("allowed_curves", &jsonschema.Schema{
		Type:        "array",
		Description: "Allowed elliptic curves",
		Items: &jsonschema.Schema{
			Type: "string",
			Enum: []any{
				"P-256",
				"P-384",
				"P-521",
				"brainpoolP256r1",
				"brainpoolP384r1",
				"brainpoolP512r1",
			},
		},
	})
	return &jsonschema.Schema{
		Type:        "object",
		Description: "Key algorithm constraints",
		Properties:  props,
	}
}

type Extensions struct {
	KeyUsage                        *KeyUsageExtension              `yaml:"keyUsage,omitempty" json:"keyUsage,omitempty" jsonschema:"description=Key usage extension requirements"`
	BasicConstraints                *BasicConstraintsExtension      `yaml:"basicConstraints,omitempty" json:"basicConstraints,omitempty" jsonschema:"description=Basic constraints extension requirements"`
	ExtendedKeyUsage                *ExtendedKeyUsageExtension      `yaml:"extendedKeyUsage,omitempty" json:"extendedKeyUsage,omitempty" jsonschema:"description=Extended key usage extension requirements"`
	SAN                             *SANExtension                   `yaml:"san,omitempty" json:"san,omitempty" jsonschema:"description=Subject Alternative Name extension requirements"`
	AuthorityKeyID                  *AuthorityKeyIDExtension        `yaml:"authorityKeyIdentifier,omitempty" json:"authorityKeyIdentifier,omitempty" jsonschema:"description=Authority Key Identifier extension requirements"`
	SubjectKeyID                    *SubjectKeyIDExtension          `yaml:"subjectKeyIdentifier,omitempty" json:"subjectKeyIdentifier,omitempty" jsonschema:"description=Subject Key Identifier extension requirements"`
	CRLDistributionPoints           *CRLDistributionPointsExtension `yaml:"crlDistributionPoints,omitempty" json:"crlDistributionPoints,omitempty" jsonschema:"description=CRL Distribution Points extension requirements"`
	AuthorityInfoAccess             *AuthorityInfoAccessExtension   `yaml:"authorityInfoAccess,omitempty" json:"authorityInfoAccess,omitempty" jsonschema:"description=Authority Information Access extension requirements"`
	CertificatePolicies             *CertificatePoliciesExtension   `yaml:"certificatePolicies,omitempty" json:"certificatePolicies,omitempty" jsonschema:"description=Certificate Policies extension requirements"`
	NameConstraints                 *NameConstraintsExtension       `yaml:"nameConstraints,omitempty" json:"nameConstraints,omitempty" jsonschema:"description=Name Constraints extension requirements"`
	PolicyConstraints               *PolicyConstraintsExtension     `yaml:"policyConstraints,omitempty" json:"policyConstraints,omitempty" jsonschema:"description=Policy Constraints extension requirements"`
	InhibitAnyPolicy                *InhibitAnyPolicyExtension      `yaml:"inhibitAnyPolicy,omitempty" json:"inhibitAnyPolicy,omitempty" jsonschema:"description=Inhibit anyPolicy extension requirements"`
	RejectUnknownCriticalExtensions bool                            `yaml:"reject_unknown_critical_extensions,omitempty" json:"reject_unknown_critical_extensions,omitempty" jsonschema:"description=Reject certificates with unknown critical extensions"`
}

type KeyUsageExtension struct {
	Critical         *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	DigitalSignature bool  `yaml:"digitalSignature,omitempty" json:"digitalSignature,omitempty" jsonschema:"description=Require digital signature usage"`
	KeyCertSign      bool  `yaml:"keyCertSign,omitempty" json:"keyCertSign,omitempty" jsonschema:"description=Require certificate signing usage"`
	CRLSign          bool  `yaml:"cRLSign,omitempty" json:"cRLSign,omitempty" jsonschema:"description=Require CRL signing usage"`
	KeyEncipherment  bool  `yaml:"keyEncipherment,omitempty" json:"keyEncipherment,omitempty" jsonschema:"description=Require key encipherment usage"`
}

type BasicConstraintsExtension struct {
	Critical          *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	PathLenConstraint *int  `yaml:"pathLenConstraint,omitempty" json:"pathLenConstraint,omitempty" jsonschema:"minimum=0,description=Required pathLenConstraint value"`
	IsCA              bool  `yaml:"isCA,omitempty" json:"isCA,omitempty" jsonschema:"description=Require certificate to be a CA"`
}

type ExtendedKeyUsageExtension struct {
	Critical   *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	ServerAuth bool  `yaml:"serverAuth,omitempty" json:"serverAuth,omitempty" jsonschema:"description=Require TLS server authentication"`
	ClientAuth bool  `yaml:"clientAuth,omitempty" json:"clientAuth,omitempty" jsonschema:"description=Require TLS client authentication"`
}

type CRLDistributionPointsExtension struct {
	Critical     *bool    `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	VerifyAccess bool     `yaml:"verifyAccess,omitempty" json:"verifyAccess,omitempty" jsonschema:"description=Verify CRL URLs are accessible"`
	URLs         []string `yaml:"urls,omitempty" json:"urls,omitempty" jsonschema:"description=Expected CRL distribution point URLs"`
}

type AuthorityInfoAccessExtension struct {
	Critical     *bool    `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	VerifyAccess bool     `yaml:"verifyAccess,omitempty" json:"verifyAccess,omitempty" jsonschema:"description=Verify URLs are accessible"`
	OCSP         []string `yaml:"ocsp,omitempty" json:"ocsp,omitempty" jsonschema:"description=Expected OCSP responder URLs"`
	CAIssuers    []string `yaml:"caIssuers,omitempty" json:"caIssuers,omitempty" jsonschema:"description=Expected CA issuer certificate URLs"`
}

type SANExtension struct {
	Critical    *bool    `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	Required    bool     `yaml:"required,omitempty" json:"required,omitempty" jsonschema:"description=SAN extension must be present"`
	Allowed     []string `yaml:"allowed,omitempty" json:"allowed,omitempty" jsonschema:"description=Allowed SAN patterns (regex)"`
	Forbidden   []string `yaml:"forbidden,omitempty" json:"forbidden,omitempty" jsonschema:"description=Forbidden SAN patterns (regex)"`
	NoWildcards bool     `yaml:"no_wildcards,omitempty" json:"no_wildcards,omitempty" jsonschema:"description=Disallow wildcard entries"`
}

type AuthorityKeyIDExtension struct {
	Critical *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	Required bool  `yaml:"required,omitempty" json:"required,omitempty" jsonschema:"description=AKI extension must be present"`
}

type SubjectKeyIDExtension struct {
	Critical *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	Required bool  `yaml:"required,omitempty" json:"required,omitempty" jsonschema:"description=SKI extension must be present"`
}

type CertificatePoliciesExtension struct {
	Critical       *bool    `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	RequiredOIDs   []string `yaml:"requiredOIDs,omitempty" json:"requiredOIDs,omitempty" jsonschema:"description=Required policy OIDs (dot notation)"`
	ForbiddenOIDs  []string `yaml:"forbiddenOIDs,omitempty" json:"forbiddenOIDs,omitempty" jsonschema:"description=Forbidden policy OIDs"`
	AllowAnyPolicy bool     `yaml:"allowAnyPolicy,omitempty" json:"allowAnyPolicy,omitempty" jsonschema:"description=Allow anyPolicy OID (2.5.29.32.0)"`
}

type NameConstraintsExtension struct {
	Critical              *bool    `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	Required              bool     `yaml:"required,omitempty" json:"required,omitempty" jsonschema:"description=Name Constraints extension must be present"`
	PermittedDNSDomains   []string `yaml:"permittedDNSDomains,omitempty" json:"permittedDNSDomains,omitempty" jsonschema:"description=Expected permitted DNS domains"`
	ExcludedDNSDomains    []string `yaml:"excludedDNSDomains,omitempty" json:"excludedDNSDomains,omitempty" jsonschema:"description=Expected excluded DNS domains"`
	PermittedEmailDomains []string `yaml:"permittedEmailDomains,omitempty" json:"permittedEmailDomains,omitempty" jsonschema:"description=Expected permitted email domains"`
	ExcludedEmailDomains  []string `yaml:"excludedEmailDomains,omitempty" json:"excludedEmailDomains,omitempty" jsonschema:"description=Expected excluded email domains"`
}

type PolicyConstraintsExtension struct {
	Critical              *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	Required              bool  `yaml:"required,omitempty" json:"required,omitempty" jsonschema:"description=Policy Constraints extension must be present"`
	RequireExplicitPolicy *int  `yaml:"requireExplicitPolicy,omitempty" json:"requireExplicitPolicy,omitempty" jsonschema:"minimum=0,description=Required requireExplicitPolicy value"`
	InhibitPolicyMapping  *int  `yaml:"inhibitPolicyMapping,omitempty" json:"inhibitPolicyMapping,omitempty" jsonschema:"minimum=0,description=Required inhibitPolicyMapping value"`
}

type InhibitAnyPolicyExtension struct {
	Critical  *bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension criticality (true=must be critical, false=must NOT be critical, null=don't check)"`
	Required  bool  `yaml:"required,omitempty" json:"required,omitempty" jsonschema:"description=Inhibit anyPolicy extension must be present"`
	SkipCerts *int  `yaml:"skipCerts,omitempty" json:"skipCerts,omitempty" jsonschema:"minimum=0,description=Required skipCerts value"`
}
