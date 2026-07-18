package zcrypto

import (
	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func malformedExtensionNode(name string, empty bool) *node.Node {
	n := node.New(name, nil)
	n.Children["malformed"] = node.New("malformed", true)
	if empty {
		n.Children["empty"] = node.New("empty", true)
	}
	return n
}

func isEmptySequence(der []byte) bool {
	input := cryptobyte.String(der)
	var sequence cryptobyte.String
	return input.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) && input.Empty() && sequence.Empty()
}
