// Package operator provides rule operators for evaluating certificate field values.
package operator

import "github.com/cavoq/PCL/internal/node"

type Operator interface {
	Name() string
	Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error)
}

var All = []Operator{
	Eq{},
	Neq{},
	Present{},
	Absent{},
	Gte{},
	Gt{},
	Lte{},
	Lt{},
	In{},
	NotIn{},
	Contains{},
	Before{},
	After{},
	Matches{},
	Positive{},
	Odd{},
	MaxLength{},
	MinLength{},
	IsCritical{},
	NotCritical{},
	IsEmpty{},
	NotEmpty{},
	Regex{},
	NotRegex{},
	SignatureValid{},
	IssuedBy{},
	AKIMatchesSKI{},
	PathLenValid{},
	ValidityPeriodDays{},
	ValidityOrderCorrect{},
	SignatureAlgorithmMatchesTBS{},
	NoUnknownCriticalExtensions{},
	SANRequiredIfEmptySubject{},
	KeyUsageCA{},
	KeyUsageLeaf{},
	EKUContains{},
	EKUNotContains{},
	EKUServerAuth{},
	EKUClientAuth{},
	NoUniqueIdentifiers{},
	SerialNumberUnique{},
	CRLValid{},
	CRLNotExpired{},
	CRLSignedBy{},
	NotRevoked{},
	OCSPValid{},
	NotRevokedOCSP{},
	OCSPGood{},
	// Generic operators
	Every{},
	DateDiff{},
	NameConstraintsValid{},
	CertificatePolicyValid{},
	IsNull{},
	// Generic component validation operators (useful for DNS labels, path segments, etc.)
	ComponentMaxLength{},
	ComponentMinLength{},
	ComponentRegex{},
	ComponentNotRegex{},
	AnyComponentMatches{},
	NoComponentMatches{},
	// CIDR range validation operators (for IP address checking)
	ComponentInCIDR{},
	ComponentNotInCIDR{},
	// PSL/TLD validation operators (for domain name checking)
	TLDRegistered{},
	TLDNotRegistered{},
	IsPublicSuffix{},
	IsNotPublicSuffix{},
	ComponentTLDRegistered{},
	ComponentTLDNotRegistered{},
	ComponentIsPublicSuffix{},
	ComponentNotPublicSuffix{},
	// UTF-8 validation operators
	UTF8NoBOM{},
	ContainsBOM{},
	// Subject DN validation operators
	NoDuplicateAttributes{},
	// Unique value operators (for AIA, CRL DP, etc.)
	UniqueValues{},
	UniqueChildren{},
	// Time format validation operators (ASN.1)
	UTCTimeHasZulu{},
	UTCTimeHasSeconds{},
	GeneralizedTimeHasZulu{},
	GeneralizedTimeNoFraction{},
	IsUTCTime{},
	IsGeneralizedTime{},
	// Encoding validation operators (ASN.1)
	IsIA5String{},
	IsPrintableString{},
	IsUTF8String{},
	ValidIA5String{},
	ValidPrintableString{},
	// DER encoding validation (Mozilla byte-for-byte requirements)
	DEREqualsHex{},
}
