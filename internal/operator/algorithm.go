package operator

import (
	"bytes"

	"github.com/cavoq/PCL/internal/node"
)

// SignatureAlgorithmMatchesTBS checks the complete encoded
// AlgorithmIdentifier, including its OID and parameters. Parsing and DER
// extraction remain the responsibility of the input builders.
type SignatureAlgorithmMatchesTBS struct{}

func (SignatureAlgorithmMatchesTBS) Name() string { return "signatureAlgorithmMatchesTBS" }

func (SignatureAlgorithmMatchesTBS) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	outer, outerFound := n.Resolve("signatureAlgorithm.rawDER")
	tbs, tbsFound := n.Resolve("tbsSignatureAlgorithm.rawDER")
	if !outerFound || !tbsFound || outer == nil || tbs == nil {
		return false, nil
	}

	outerDER, outerOK := outer.Value.([]byte)
	tbsDER, tbsOK := tbs.Value.([]byte)
	if !outerOK || !tbsOK || len(outerDER) == 0 || len(tbsDER) == 0 {
		return false, nil
	}

	return bytes.Equal(outerDER, tbsDER), nil
}
