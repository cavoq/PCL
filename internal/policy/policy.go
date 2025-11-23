package policy

type Policy struct {
	Name        string          `yaml:"name,omitempty"`
	Description string          `yaml:"description,omitempty"`
	Validity    *ValidityRule   `yaml:"validity,omitempty"`
	Subject     *NameRule       `yaml:"subject,omitempty"`
	Issuer      *NameRule       `yaml:"issuer,omitempty"`
	Crypto      *CryptoRule     `yaml:"crypto,omitempty"`
	Extensions  *Extensions     `yaml:"extensions,omitempty"`
	Revocation  *RevocationRule `yaml:"revocation,omitempty"`
}

type ValidityRule struct {
	MinDays *int `yaml:"min_days,omitempty"`
	MaxDays *int `yaml:"max_days,omitempty"`
}

type NameRule struct {
	Allowed     []string `yaml:"allowed,omitempty"`
	Forbidden   []string `yaml:"forbidden,omitempty"`
	NoWildcards bool     `yaml:"no_wildcards,omitempty"`
}

type CryptoRule struct {
	SubjectPublicKeyInfo *SubjectPublicKeyInfoRule `yaml:"subjectPublicKeyInfo,omitempty"`
	SignatureAlgorithm   *SignatureAlgorithmRule   `yaml:"signatureAlgorithm,omitempty"`
}

type SubjectPublicKeyInfoRule struct {
	AllowedAlgorithms map[string]*KeyAlgorithmRule `yaml:"allowed_algorithms,omitempty"`
}

type SignatureAlgorithmRule struct {
	AllowedAlgorithms []string `yaml:"allowed_algorithms,omitempty"`
}

type KeyAlgorithmRule struct {
	MinSize       int      `yaml:"min_size,omitempty"`       // For RSA and EC
	AllowedCurves []string `yaml:"allowed_curves,omitempty"` // Only for EC
}

type Extensions struct {
	KeyUsage              *KeyUsageExtension         `yaml:"keyUsage,omitempty"`
	BasicConstraints      *BasicConstraintsExtension `yaml:"basicConstraints,omitempty"`
	ExtendedKeyUsage      *ExtendedKeyUsageExtension `yaml:"extendedKeyUsage,omitempty"`
	SAN                   *NameRule                  `yaml:"san,omitempty"`
	CRLDistributionPoints *RevocationExtension       `yaml:"crlDistributionPoints,omitempty"`
	AuthorityInfoAccess   *RevocationExtension       `yaml:"authorityInfoAccess,omitempty"`
}

type KeyUsageExtension struct {
	Critical         bool `yaml:"critical,omitempty"`
	DigitalSignature bool `yaml:"digitalSignature,omitempty"`
	KeyCertSign      bool `yaml:"keyCertSign,omitempty"`
	CRLSign          bool `yaml:"cRLSign,omitempty"`
	KeyEncipherment  bool `yaml:"keyEncipherment,omitempty"`
}

type BasicConstraintsExtension struct {
	Critical          bool `yaml:"critical,omitempty"`
	PathLenConstraint int  `yaml:"pathLenConstraint,omitempty"`
}

type ExtendedKeyUsageExtension struct {
	ServerAuth bool `yaml:"serverAuth,omitempty"`
	ClientAuth bool `yaml:"clientAuth,omitempty"`
}

type RevocationExtension struct {
	// Can be extended if needed
}

type RevocationRule struct {
	VerifyAccess bool `yaml:"verifyAccess,omitempty"`
}
