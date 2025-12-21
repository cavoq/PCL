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
	MaxLength{},
	MinLength{},
	IsCritical{},
	NotCritical{},
	IsEmpty{},
	NotEmpty{},
	Regex{},
	NotRegex{},
	SignedBy{},
	IssuedBy{},
	AKIMatchesSKI{},
	PathLenValid{},
	ValidityPeriodDays{},
	SANRequiredIfEmptySubject{},
	KeyUsageCA{},
	KeyUsageLeaf{},
	EKUContains{},
	EKUNotContains{},
	EKUServerAuth{},
	EKUClientAuth{},
	NoUniqueIdentifiers{},
	SerialNumberUnique{},
}
