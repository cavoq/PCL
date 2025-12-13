package policy

import (
	"encoding/asn1"
	"encoding/json"

	"github.com/invopop/jsonschema"
)

var (
	OIDKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDSAN              = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDCRLDistPoints    = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDAIA              = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDAKI              = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDSKI              = asn1.ObjectIdentifier{2, 5, 29, 14}
)

type PolicyChain struct {
	Name     string
	Policies []*Policy
}

type Policy struct {
	Name        string           `yaml:"name" json:"name" jsonschema:"required,description=Policy name"`
	CertOrder   *int             `yaml:"cert_order" json:"cert_order" jsonschema:"required,minimum=0,description=Position in certificate chain (0=leaf 1=intermediate 2=root)"`
	Description string           `yaml:"description,omitempty" json:"description,omitempty" jsonschema:"description=Detailed policy description"`
	BasicFields *BasicFieldsRule `yaml:"basic_fields,omitempty" json:"basic_fields,omitempty" jsonschema:"description=RFC 5280 basic certificate field requirements"`
	Validity    *ValidityRule    `yaml:"validity,omitempty" json:"validity,omitempty" jsonschema:"description=Certificate validity constraints"`
	Subject     *NameRule        `yaml:"subject,omitempty" json:"subject,omitempty" jsonschema:"description=Subject name requirements"`
	Issuer      *NameRule        `yaml:"issuer,omitempty" json:"issuer,omitempty" jsonschema:"description=Issuer name requirements"`
	Crypto      *CryptoRule      `yaml:"crypto,omitempty" json:"crypto,omitempty" jsonschema:"description=Cryptographic requirements"`
	Extensions  *Extensions      `yaml:"extensions,omitempty" json:"extensions,omitempty" jsonschema:"description=X.509 extension requirements"`
}

type ValidityRule struct {
	MinDays *int `yaml:"min_days,omitempty" json:"min_days,omitempty" jsonschema:"minimum=1,description=Minimum validity period in days"`
	MaxDays *int `yaml:"max_days,omitempty" json:"max_days,omitempty" jsonschema:"minimum=1,description=Maximum validity period in days"`
}

// BasicFieldsRule defines RFC 5280 basic certificate field requirements
type BasicFieldsRule struct {
	// Version validation (RFC 5280 Section 4.1.2.1)
	RequireV3 bool `yaml:"require_v3,omitempty" json:"require_v3,omitempty" jsonschema:"description=Require X.509 v3 certificates (recommended for certificates with extensions)"`

	// Serial number validation (RFC 5280 Section 4.1.2.2)
	SerialNumber *SerialNumberRule `yaml:"serial_number,omitempty" json:"serial_number,omitempty" jsonschema:"description=Serial number requirements per RFC 5280"`

	// Unique identifiers validation (RFC 5280 Section 4.1.2.8)
	RejectUniqueIdentifiers bool `yaml:"reject_unique_identifiers,omitempty" json:"reject_unique_identifiers,omitempty" jsonschema:"description=Reject certificates with deprecated unique identifiers (issuerUniqueID/subjectUniqueID)"`
}

// SerialNumberRule defines serial number validation requirements per RFC 5280 Section 4.1.2.2
type SerialNumberRule struct {
	// RequirePositive ensures serial number is a positive integer (RFC 5280 requirement)
	RequirePositive bool `yaml:"require_positive,omitempty" json:"require_positive,omitempty" jsonschema:"description=Serial number must be a positive integer per RFC 5280"`

	// MaxLength is the maximum length in octets (RFC 5280 limits to 20 octets)
	MaxLength *int `yaml:"max_length,omitempty" json:"max_length,omitempty" jsonschema:"minimum=1,maximum=20,description=Maximum serial number length in octets (RFC 5280 maximum is 20)"`
}

type NameRule struct {
	Allowed     []string `yaml:"allowed,omitempty" json:"allowed,omitempty" jsonschema:"description=List of allowed name patterns (regex supported)"`
	Forbidden   []string `yaml:"forbidden,omitempty" json:"forbidden,omitempty" jsonschema:"description=List of forbidden name patterns (regex supported)"`
	NoWildcards bool     `yaml:"no_wildcards,omitempty" json:"no_wildcards,omitempty" jsonschema:"description=Disallow wildcard certificates"`
}

type CryptoRule struct {
	SubjectPublicKeyInfo *SubjectPublicKeyInfoRule `yaml:"subjectPublicKeyInfo,omitempty" json:"subjectPublicKeyInfo,omitempty" jsonschema:"description=Public key algorithm constraints"`
	SignatureAlgorithm   *SignatureAlgorithmRule   `yaml:"signatureAlgorithm,omitempty" json:"signatureAlgorithm,omitempty" jsonschema:"description=Signature algorithm constraints"`
}

type SubjectPublicKeyInfoRule struct {
	AllowedAlgorithms map[string]*KeyAlgorithmRule `yaml:"allowed_algorithms,omitempty" json:"allowed_algorithms,omitempty" jsonschema:"description=Allowed public key algorithms and their constraints"`
}

type SignatureAlgorithmRule struct {
	AllowedAlgorithms []string `yaml:"allowed_algorithms,omitempty" json:"allowed_algorithms,omitempty" jsonschema:"description=List of allowed signature algorithms"`
}

func (SignatureAlgorithmRule) JSONSchema() *jsonschema.Schema {
	props := jsonschema.NewProperties()
	props.Set("allowed_algorithms", &jsonschema.Schema{
		Type:        "array",
		Description: "List of allowed signature algorithms. Values match Go's x509.SignatureAlgorithm.String() output.",
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
		Description: "Allowed elliptic curves. Values match Go's ecdsa.PublicKey.Params().Name output.",
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
	KeyUsage              *KeyUsageExtension              `yaml:"keyUsage,omitempty" json:"keyUsage,omitempty" jsonschema:"description=Key usage extension requirements"`
	BasicConstraints      *BasicConstraintsExtension      `yaml:"basicConstraints,omitempty" json:"basicConstraints,omitempty" jsonschema:"description=Basic constraints extension requirements"`
	ExtendedKeyUsage      *ExtendedKeyUsageExtension      `yaml:"extendedKeyUsage,omitempty" json:"extendedKeyUsage,omitempty" jsonschema:"description=Extended key usage extension requirements"`
	SAN                   *NameRule                       `yaml:"san,omitempty" json:"san,omitempty" jsonschema:"description=Subject Alternative Name requirements"`
	CRLDistributionPoints *CRLDistributionPointsExtension `yaml:"crlDistributionPoints,omitempty" json:"crlDistributionPoints,omitempty" jsonschema:"description=CRL Distribution Points extension"`
	AuthorityInfoAccess   *AuthorityInfoAccessExtension   `yaml:"authorityInfoAccess,omitempty" json:"authorityInfoAccess,omitempty" jsonschema:"description=Authority Information Access extension"`
}

type KeyUsageExtension struct {
	Critical         bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension must be marked critical"`
	DigitalSignature bool `yaml:"digitalSignature,omitempty" json:"digitalSignature,omitempty" jsonschema:"description=Digital signature usage"`
	KeyCertSign      bool `yaml:"keyCertSign,omitempty" json:"keyCertSign,omitempty" jsonschema:"description=Certificate signing (CA only)"`
	CRLSign          bool `yaml:"cRLSign,omitempty" json:"cRLSign,omitempty" jsonschema:"description=CRL signing (CA only)"`
	KeyEncipherment  bool `yaml:"keyEncipherment,omitempty" json:"keyEncipherment,omitempty" jsonschema:"description=Key encipherment usage"`
}

type BasicConstraintsExtension struct {
	Critical          bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension must be marked critical (required for CA certificates per RFC 5280)"`
	PathLenConstraint *int `yaml:"pathLenConstraint,omitempty" json:"pathLenConstraint,omitempty" jsonschema:"minimum=0,description=Maximum number of subordinate CAs in the chain"`
	IsCA              bool `yaml:"isCA,omitempty" json:"isCA,omitempty" jsonschema:"description=Certificate is a Certificate Authority"`
}

type ExtendedKeyUsageExtension struct {
	Critical   bool `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension must be marked critical"`
	ServerAuth bool `yaml:"serverAuth,omitempty" json:"serverAuth,omitempty" jsonschema:"description=TLS server authentication (id-kp-serverAuth)"`
	ClientAuth bool `yaml:"clientAuth,omitempty" json:"clientAuth,omitempty" jsonschema:"description=TLS client authentication (id-kp-clientAuth)"`
}

type CRLDistributionPointsExtension struct {
	Critical     bool     `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension must be marked critical"`
	VerifyAccess bool     `yaml:"verifyAccess,omitempty" json:"verifyAccess,omitempty" jsonschema:"description=Verify that CRL URLs are accessible"`
	URLs         []string `yaml:"urls,omitempty" json:"urls,omitempty" jsonschema:"description=Expected CRL distribution point URLs"`
}

type AuthorityInfoAccessExtension struct {
	Critical     bool     `yaml:"critical,omitempty" json:"critical,omitempty" jsonschema:"description=Extension must be marked critical"`
	VerifyAccess bool     `yaml:"verifyAccess,omitempty" json:"verifyAccess,omitempty" jsonschema:"description=Verify that URLs are accessible"`
	OCSP         []string `yaml:"ocsp,omitempty" json:"ocsp,omitempty" jsonschema:"description=Expected OCSP responder URLs"`
	CAIssuers    []string `yaml:"caIssuers,omitempty" json:"caIssuers,omitempty" jsonschema:"description=Expected CA issuer certificate URLs"`
}
