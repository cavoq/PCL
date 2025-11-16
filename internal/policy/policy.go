package policy

type Policy struct {
	Validity   *ValidityRule   `yaml:"validity,omitempty"`
	Subject    *NameRule       `yaml:"subject,omitempty"`
	Issuer     *NameRule       `yaml:"issuer,omitempty"`
	Crypto     *CryptoRule     `yaml:"crypto,omitempty"`
	Extensions *Extensions     `yaml:"extensions,omitempty"`
	Revocation *RevocationRule `yaml:"revocation,omitempty"`
}

type ValidityRule struct {
	MinExpiryDays *int `yaml:"min_expiry_days,omitempty"`
	MaxExpiryDays *int `yaml:"max_expiry_days,omitempty"`
}

type NameRule struct {
	Allowed     []string `yaml:"allowed,omitempty"`
	Forbidden   []string `yaml:"forbidden,omitempty"`
	NoWildcards bool     `yaml:"no_wildcards,omitempty"`
}

type CryptoRule struct {
	MinKeySize map[string]int `yaml:"min_key_size,omitempty"`
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
	//
}

type RevocationRule struct {
	VerifyAccess bool `yaml:"verifyAccess,omitempty"`
}
