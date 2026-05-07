package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

// IsNull checks if the node represents an ASN.1 NULL value.
// Used for checking AlgorithmIdentifier parameters per RFC 4055.
// Returns true when:
// - Node exists and has null=true child
// Returns false when:
// - Node is nil (parameters are absent, not NULL)
// - Node exists but null is not true
type IsNull struct{}

func (IsNull) Name() string { return "isNull" }

func (IsNull) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		// Parameters absent - not the same as NULL
		return false, nil
	}

	nullNode, ok := n.Children["null"]
	if !ok {
		return false, nil
	}

	if v, ok := nullNode.Value.(bool); ok {
		return v, nil
	}

	return false, nil
}