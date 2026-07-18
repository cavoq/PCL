package operator

import (
	"testing"

	"github.com/cavoq/PCL/internal/node"
)

func algorithmPair(outer, tbs []byte) *node.Node {
	root := node.New("certificate", nil)
	root.Children["signatureAlgorithm"] = node.New("signatureAlgorithm", nil)
	root.Children["signatureAlgorithm"].Children["rawDER"] = node.New("rawDER", outer)
	root.Children["tbsSignatureAlgorithm"] = node.New("tbsSignatureAlgorithm", nil)
	root.Children["tbsSignatureAlgorithm"].Children["rawDER"] = node.New("rawDER", tbs)
	return root
}

func TestSignatureAlgorithmMatchesTBS(t *testing.T) {
	op := SignatureAlgorithmMatchesTBS{}
	tests := []struct {
		name string
		node *node.Node
		want bool
	}{
		{name: "same identifier", node: algorithmPair([]byte{0x30, 0x00}, []byte{0x30, 0x00}), want: true},
		{name: "different identifier", node: algorithmPair([]byte{0x30, 0x00}, []byte{0x30, 0x01})},
		{name: "empty identifier", node: algorithmPair(nil, nil)},
		{name: "missing identifiers", node: node.New("certificate", nil)},
		{name: "nil node"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := op.Evaluate(tt.node, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("SignatureAlgorithmMatchesTBS = %v, want %v", got, tt.want)
			}
		})
	}
}
