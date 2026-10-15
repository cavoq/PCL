package operator

import (
	"fmt"
	"slices"

	"github.com/zmap/zcrypto/x509"

	certpkg "github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
)

// CertificatePolicyValid runs the RFC 5280 Section 6.1 certificate policy
// processing over the path from the trust anchor to the evaluated
// certificate, honoring policy mappings, requireExplicitPolicy,
// inhibitPolicyMapping and inhibitAnyPolicy.
//
// First-class CertificatePolicyInputs model the four independent RFC 5280
// inputs. Without them, operands retain the compatibility behavior: operands
// are the user-initial-policy-set and also set initial-explicit-policy;
// without operands the RFC default inputs apply. anyPolicy accepts any valid
// path policy. A CA mapping to or from anyPolicy always fails.
//
// The self-signed top of the chain is the trust anchor and is not processed
// unless it is the evaluated certificate itself. Malformed policy extensions
// fail the check.
type CertificatePolicyValid struct{}

// CertificatePolicyInputs are the user-supplied RFC 5280 Section 6.1.1
// inputs. InitialPolicySet defaults to anyPolicy when Configured is true and
// the slice is empty. Configured distinguishes explicit default inputs from
// the legacy operator mode, where operands imply initial-explicit-policy.
type CertificatePolicyInputs struct {
	Configured                  bool
	InitialPolicySet            []string
	InitialExplicitPolicy       bool
	InitialPolicyMappingInhibit bool
	InitialAnyPolicyInhibit     bool
}

// IsConfigured reports whether the caller selected the first-class RFC 5280
// inputs. Non-default values imply configuration for programmatic callers;
// Configured also represents an explicitly selected all-default input set.
func (inputs CertificatePolicyInputs) IsConfigured() bool {
	return inputs.Configured || len(inputs.InitialPolicySet) > 0 ||
		inputs.InitialExplicitPolicy || inputs.InitialPolicyMappingInhibit ||
		inputs.InitialAnyPolicyInhibit
}

func (CertificatePolicyValid) Name() string { return "certificatePolicyValid" }

func (CertificatePolicyValid) Evaluate(_ *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if !ctx.HasCert() || !ctx.HasChain() {
		return false, nil
	}

	inputs := certificatePolicyInputs(ctx.CertificatePolicyInputs, operands)

	path, ok := certificatePolicyPath(ctx)
	if !ok {
		return false, nil
	}
	facts := make([]certificatePolicyFacts, 0, len(path))
	for _, certificate := range path {
		certificateFacts, err := decodeCertificatePolicyFacts(certificate)
		if err != nil {
			return false, nil
		}
		facts = append(facts, certificateFacts)
	}
	return processCertificatePolicies(facts, inputs), nil
}

func certificatePolicyInputs(configured CertificatePolicyInputs, operands []any) CertificatePolicyInputs {
	if configured.IsConfigured() {
		configured.Configured = true
		if len(configured.InitialPolicySet) == 0 {
			configured.InitialPolicySet = []string{oid.AnyPolicy}
		}
		return configured
	}

	var acceptable []string
	for _, operand := range operands {
		if policy, ok := operand.(string); ok {
			acceptable = append(acceptable, policy)
		}
	}
	if len(acceptable) == 0 {
		acceptable = []string{oid.AnyPolicy}
	}
	return CertificatePolicyInputs{
		InitialPolicySet:      acceptable,
		InitialExplicitPolicy: len(operands) > 0,
	}
}

// certificatePolicyPath returns the certificates from the one issued by the
// trust anchor (RFC 5280 certificate 1) down to the evaluated certificate
// (certificate n).
func certificatePolicyPath(ctx *EvaluationContext) ([]*x509.Certificate, bool) {
	target := slices.IndexFunc(ctx.Chain, func(info *certpkg.Info) bool {
		return info != nil && info.Cert == ctx.Cert.Cert
	})
	if target < 0 {
		return nil, false
	}

	top := len(ctx.Chain) - 1
	if top > target && ctx.Chain[top] != nil && ctx.Chain[top].Cert != nil &&
		certpkg.IsSelfSigned(ctx.Chain[top].Cert) {
		top-- // trust anchor
	}

	path := make([]*x509.Certificate, 0, top-target+1)
	for index := top; index >= target; index-- {
		if ctx.Chain[index] == nil || ctx.Chain[index].Cert == nil {
			return nil, false
		}
		path = append(path, ctx.Chain[index].Cert)
	}
	return path, true
}

type certificatePolicyFacts struct {
	hasPolicies bool
	policies    []string
	mappings    []x509ext.PolicyMapping
	// Counters are -1 when absent or too large to constrain a path.
	requireExplicitPolicy int
	inhibitPolicyMapping  int
	inhibitAnyPolicy      int
	selfIssued            bool
}

func decodeCertificatePolicyFacts(certificate *x509.Certificate) (certificatePolicyFacts, error) {
	facts := certificatePolicyFacts{
		requireExplicitPolicy: -1,
		inhibitPolicyMapping:  -1,
		inhibitAnyPolicy:      -1,
		selfIssued:            certpkg.IsSelfIssued(certificate),
	}
	extensions := x509ext.NewExtensionIndex(certificate.Extensions)

	value, present, err := policyExtensionValue(extensions, oid.CertificatePolicies)
	if err != nil {
		return facts, err
	}
	if present {
		policies, err := x509ext.DecodeCertificatePolicyIdentifiersStrict(value)
		if err != nil {
			return facts, err
		}
		facts.hasPolicies, facts.policies = true, policies
	} else if len(certificate.PolicyIdentifiers) > 0 {
		// Typed facts supplied without the raw extension.
		facts.hasPolicies = true
		for _, identifier := range certificate.PolicyIdentifiers {
			facts.policies = append(facts.policies, identifier.String())
		}
	}

	value, present, err = policyExtensionValue(extensions, oid.PolicyMappings)
	if err != nil {
		return facts, err
	}
	if present {
		mappings, err := x509ext.DecodePolicyMappingsStrict(value)
		if err != nil {
			return facts, err
		}
		facts.mappings = mappings
	}

	value, present, err = policyExtensionValue(extensions, oid.PolicyConstraints)
	if err != nil {
		return facts, err
	}
	if present {
		constraints, err := x509ext.DecodePolicyConstraintsStrict(value)
		if err != nil {
			return facts, err
		}
		if constraints.RequireExplicitPolicyPresent && constraints.RequireExplicitPolicyFitsInt {
			facts.requireExplicitPolicy = constraints.RequireExplicitPolicy
		}
		if constraints.InhibitPolicyMappingPresent && constraints.InhibitPolicyMappingFitsInt {
			facts.inhibitPolicyMapping = constraints.InhibitPolicyMapping
		}
	}

	value, present, err = policyExtensionValue(extensions, oid.InhibitAnyPolicy)
	if err != nil {
		return facts, err
	}
	if present {
		skipCerts, err := x509ext.DecodeInhibitAnyPolicyStrict(value)
		if err != nil {
			return facts, err
		}
		if skipCerts.FitsInt {
			facts.inhibitAnyPolicy = skipCerts.Int
		}
	}
	return facts, nil
}

func policyExtensionValue(
	extensions x509ext.ExtensionIndex,
	identifier string,
) ([]byte, bool, error) {
	match := extensions.Lookup(identifier)
	if !match.Present() {
		return nil, false, nil
	}
	extension, unique := match.Extension()
	if !unique {
		return nil, true, fmt.Errorf("duplicate certificate extension %s", identifier)
	}
	return extension.Value, true, nil
}

// processCertificatePolicies applies the RFC 5280 Section 6.1 policy steps
// (6.1.3 (d)-(f), 6.1.4 (a)(b)(h)-(j), 6.1.5 (a)(b)(g)) to certificates 1..n.
// With explicit policy required, the path is valid only when the
// valid_policy_tree is non-NULL after intersecting it with the initial policy
// set. Otherwise a NULL tree is allowed unless a certificate constraint
// drives explicit-policy to zero.
func processCertificatePolicies(path []certificatePolicyFacts, inputs CertificatePolicyInputs) bool {
	n := len(path)
	explicitPolicy := n + 1
	if inputs.InitialExplicitPolicy {
		explicitPolicy = 0
	}
	inhibitAnyPolicy := n + 1
	if inputs.InitialAnyPolicyInhibit {
		inhibitAnyPolicy = 0
	}
	policyMapping := n + 1
	if inputs.InitialPolicyMappingInhibit {
		policyMapping = 0
	}
	tree := newPolicyTree()

	for i := 1; i <= n; i++ {
		certificate := path[i-1]
		switch {
		case !certificate.hasPolicies:
			tree.root = nil // 6.1.3 (e)
		case tree.root != nil:
			allowAnyPolicy := inhibitAnyPolicy > 0 || (i < n && certificate.selfIssued)
			tree.addCertificatePolicies(i, certificate.policies, allowAnyPolicy)
		}
		if explicitPolicy == 0 && tree.root == nil {
			return false // 6.1.3 (f)
		}
		if i == n {
			break
		}

		if !tree.applyPolicyMappings(i, certificate.mappings, policyMapping > 0) {
			return false // 6.1.4 (a): anyPolicy must not be mapped
		}
		if !certificate.selfIssued {
			explicitPolicy = max(explicitPolicy-1, 0)
			policyMapping = max(policyMapping-1, 0)
			inhibitAnyPolicy = max(inhibitAnyPolicy-1, 0)
		}
		if certificate.requireExplicitPolicy >= 0 {
			explicitPolicy = min(explicitPolicy, certificate.requireExplicitPolicy)
		}
		if certificate.inhibitPolicyMapping >= 0 {
			policyMapping = min(policyMapping, certificate.inhibitPolicyMapping)
		}
		if certificate.inhibitAnyPolicy >= 0 {
			inhibitAnyPolicy = min(inhibitAnyPolicy, certificate.inhibitAnyPolicy)
		}
	}

	explicitPolicy = max(explicitPolicy-1, 0) // 6.1.5 (a)
	if path[n-1].requireExplicitPolicy == 0 {
		explicitPolicy = 0 // 6.1.5 (b)
	}
	tree.intersect(n, inputs.InitialPolicySet) // 6.1.5 (g)
	return explicitPolicy > 0 || tree.root != nil
}

type policyNode struct {
	validPolicy string
	expected    []string
	parent      *policyNode
	children    []*policyNode
}

func (n *policyNode) addChild(validPolicy string, expected []string) {
	n.children = append(n.children, &policyNode{
		validPolicy: validPolicy,
		expected:    expected,
		parent:      n,
	})
}

func (n *policyNode) hasChild(validPolicy string) bool {
	return slices.ContainsFunc(n.children, func(child *policyNode) bool {
		return child.validPolicy == validPolicy
	})
}

// policyTree is the RFC 5280 valid_policy_tree; a nil root is NULL.
type policyTree struct {
	root *policyNode
}

func newPolicyTree() *policyTree {
	return &policyTree{root: &policyNode{validPolicy: oid.AnyPolicy, expected: []string{oid.AnyPolicy}}}
}

func (tree *policyTree) nodesAtDepth(depth int) []*policyNode {
	if tree.root == nil {
		return nil
	}
	level := []*policyNode{tree.root}
	for ; depth > 0; depth-- {
		var next []*policyNode
		for _, n := range level {
			next = append(next, n.children...)
		}
		level = next
	}
	return level
}

// addCertificatePolicies implements 6.1.3 (d) for certificate i.
func (tree *policyTree) addCertificatePolicies(i int, policies []string, allowAnyPolicy bool) {
	parents := tree.nodesAtDepth(i - 1)
	for _, policy := range policies {
		if policy == oid.AnyPolicy {
			continue
		}
		matched := false
		for _, parent := range parents {
			if slices.Contains(parent.expected, policy) {
				parent.addChild(policy, []string{policy})
				matched = true
			}
		}
		if matched {
			continue
		}
		for _, parent := range parents {
			if parent.validPolicy == oid.AnyPolicy {
				parent.addChild(policy, []string{policy})
			}
		}
	}

	if allowAnyPolicy && slices.Contains(policies, oid.AnyPolicy) {
		for _, parent := range parents {
			for _, expected := range parent.expected {
				if !parent.hasChild(expected) {
					parent.addChild(expected, []string{expected})
				}
			}
		}
	}
	tree.prune(i)
}

// applyPolicyMappings implements 6.1.4 (a) and (b) for certificate i. It
// reports false when a mapping involves anyPolicy.
func (tree *policyTree) applyPolicyMappings(i int, mappings []x509ext.PolicyMapping, allowed bool) bool {
	var issuerPolicies []string
	subjectPolicies := make(map[string][]string)
	for _, mapping := range mappings {
		if mapping.IssuerDomainPolicy == oid.AnyPolicy || mapping.SubjectDomainPolicy == oid.AnyPolicy {
			return false
		}
		if _, seen := subjectPolicies[mapping.IssuerDomainPolicy]; !seen {
			issuerPolicies = append(issuerPolicies, mapping.IssuerDomainPolicy)
		}
		if !slices.Contains(subjectPolicies[mapping.IssuerDomainPolicy], mapping.SubjectDomainPolicy) {
			subjectPolicies[mapping.IssuerDomainPolicy] = append(
				subjectPolicies[mapping.IssuerDomainPolicy],
				mapping.SubjectDomainPolicy,
			)
		}
	}

	for _, issuerPolicy := range issuerPolicies {
		var mapped, anyPolicyNode *policyNode
		for _, n := range tree.nodesAtDepth(i) {
			switch n.validPolicy {
			case issuerPolicy:
				mapped = n
				if allowed {
					n.expected = slices.Clone(subjectPolicies[issuerPolicy])
				} else {
					tree.remove(n)
				}
			case oid.AnyPolicy:
				anyPolicyNode = n
			}
		}
		if allowed && mapped == nil && anyPolicyNode != nil {
			anyPolicyNode.parent.addChild(issuerPolicy, slices.Clone(subjectPolicies[issuerPolicy]))
		}
	}
	if !allowed {
		tree.prune(i)
	}
	return true
}

// intersect implements 6.1.5 (g) for a path of n certificates.
func (tree *policyTree) intersect(n int, acceptable []string) {
	if tree.root == nil || slices.Contains(acceptable, oid.AnyPolicy) {
		return
	}

	var validPolicyNodes []*policyNode
	tree.walk(func(candidate *policyNode) {
		if candidate.parent != nil && candidate.parent.validPolicy == oid.AnyPolicy {
			validPolicyNodes = append(validPolicyNodes, candidate)
		}
	})
	for _, candidate := range validPolicyNodes {
		if candidate.validPolicy != oid.AnyPolicy && !slices.Contains(acceptable, candidate.validPolicy) {
			tree.remove(candidate)
		}
	}

	for _, anyPolicyLeaf := range tree.nodesAtDepth(n) {
		if anyPolicyLeaf.validPolicy != oid.AnyPolicy || anyPolicyLeaf.parent == nil {
			continue
		}
		for _, policy := range acceptable {
			if !slices.ContainsFunc(validPolicyNodes, func(candidate *policyNode) bool {
				return candidate.validPolicy == policy
			}) {
				anyPolicyLeaf.parent.addChild(policy, []string{policy})
			}
		}
		tree.remove(anyPolicyLeaf)
	}
	tree.prune(n)
}

func (tree *policyTree) walk(visit func(*policyNode)) {
	if tree.root == nil {
		return
	}
	pending := []*policyNode{tree.root}
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		visit(current)
		pending = append(pending, current.children...)
	}
}

func (tree *policyTree) remove(target *policyNode) {
	if target.parent == nil {
		tree.root = nil
		return
	}
	target.parent.children = slices.DeleteFunc(target.parent.children, func(child *policyNode) bool {
		return child == target
	})
}

// prune deletes nodes of depth below depth that have no children, deepest
// first, and sets the tree to NULL when the root is deleted.
func (tree *policyTree) prune(depth int) {
	for level := depth - 1; level >= 0; level-- {
		for _, n := range tree.nodesAtDepth(level) {
			if len(n.children) == 0 {
				tree.remove(n)
			}
		}
	}
}
