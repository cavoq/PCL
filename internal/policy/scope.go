package policy

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/rule"
)

const (
	InputCert     = "cert"
	InputCRL      = "crl"
	InputOCSP     = "ocsp"
	InputTST      = "tst"
	InputSCT      = "sct"
	InputAttrCert = "attrCert"
)

// inputKind is the policy-facing identity of an evaluation input. It is kept
// distinct from node namespaces (for example, "cert" versus "certificate")
// and certificate roles (for example, "leaf" or "root").
type inputKind string

const (
	certificateInput inputKind = InputCert
	crlInput         inputKind = InputCRL
	ocspInput        inputKind = InputOCSP
	tstInput         inputKind = InputTST
	sctInput         inputKind = InputSCT
	attrCertInput    inputKind = InputAttrCert
)

type inputSet map[inputKind]struct{}

func (set inputSet) add(input inputKind) {
	set[input] = struct{}{}
}

func (set inputSet) contains(input inputKind) bool {
	_, ok := set[input]
	return ok
}

// ruleScope separates the input that executes a rule from inputs referenced by
// its condition. A condition is a dependency of the rule; it never moves the
// rule to another evaluation pass.
type ruleScope struct {
	primary          inputKind
	primaryQualified bool
	dependencies     inputSet
}

func scopeForRule(candidate rule.Rule) ruleScope {
	primary, qualified := inputKindFromTarget(candidate.Target)
	scope := ruleScope{
		primary:          primary,
		primaryQualified: qualified,
		dependencies:     make(inputSet),
	}

	if candidate.When != nil {
		if dependency, ok := inputKindFromTarget(candidate.When.Target); ok {
			scope.dependencies.add(dependency)
		}
	}
	return scope
}

func (scope ruleScope) appliesTo(input inputKind) bool {
	return !scope.primaryQualified || scope.primary == input
}

type policyScope struct {
	inputs inputSet
	all    bool
}

func scopeForPolicy(candidate Policy) policyScope {
	scope := policyScope{inputs: make(inputSet)}
	if len(candidate.AppliesTo) > 0 {
		for _, input := range candidate.AppliesTo {
			scope.inputs.add(inputKind(input))
		}
		return scope
	}

	if len(candidate.Rules) == 0 {
		scope.all = true
		return scope
	}

	for _, candidateRule := range candidate.Rules {
		ruleScope := scopeForRule(candidateRule)
		if !ruleScope.primaryQualified {
			// An unqualified target addresses the current tree and can therefore
			// execute for every input. Its position in the policy must not affect
			// policy selection.
			scope.all = true
			continue
		}
		scope.inputs.add(ruleScope.primary)
	}
	return scope
}

func (scope policyScope) appliesTo(input inputKind) bool {
	return scope.all || scope.inputs.contains(input)
}

func inputKindFromTarget(target string) (inputKind, bool) {
	namespace, ok := node.InputNamespace(target)
	if !ok {
		return "", false
	}
	return inputKindFromNamespace(namespace)
}

func inputKindFromNamespace(namespace string) (inputKind, bool) {
	switch namespace {
	case node.CertificateNamespace:
		return certificateInput, true
	case node.CRLNamespace:
		return crlInput, true
	case node.OCSPNamespace:
		return ocspInput, true
	case node.TSTNamespace:
		return tstInput, true
	case node.SCTNamespace:
		return sctInput, true
	case node.AttrCertNamespace:
		return attrCertInput, true
	default:
		return "", false
	}
}

func inputKindFromContext(ctx *operator.EvaluationContext) inputKind {
	if ctx == nil {
		return certificateInput
	}

	// The tree is the object being evaluated and is therefore the strongest
	// source when a context carries additional certificate evidence.
	if ctx.Root != nil {
		if input, ok := inputKindFromNamespace(ctx.Root.Name); ok {
			return input
		}
	}

	if ctx.Cert != nil {
		switch ctx.Cert.Type {
		case InputCRL:
			return crlInput
		case InputOCSP:
			return ocspInput
		case InputTST:
			return tstInput
		case InputSCT:
			return sctInput
		case InputAttrCert:
			return attrCertInput
		}
	}

	// Certificate roles such as leaf, intermediate, root, and ocspSigning all
	// belong to the certificate input pass. This is also the compatibility
	// default for callers that do not provide an evaluation context.
	return certificateInput
}

func inputTypeFromContext(ctx *operator.EvaluationContext) string {
	return string(inputKindFromContext(ctx))
}
