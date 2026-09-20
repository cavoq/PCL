package zcrypto

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
	"golang.org/x/crypto/cryptobyte"
)

// projectReasonFlags preserves the certificate node schema, which exposes
// only asserted ReasonFlags as named children. CRL projection intentionally
// exposes every named flag as a boolean and remains a separate adapter.
func projectReasonFlags(decoded *x509ext.ReasonFlags) *node.Node {
	n := node.New("reasons", nil)
	n.Children["present"] = node.New("present", true)
	// Preserve the byte-slice representation exposed by the original parser.
	n.Children["raw"] = node.New("raw", cryptobyte.String(decoded.RawDER))
	n.Children["unusedBits"] = node.New("unusedBits", decoded.UnusedBits)
	n.Children["value"] = node.New("value", cryptobyte.String(decoded.Value))
	for _, descriptor := range x509ext.ReasonFlagDescriptors() {
		if decoded.Mask&descriptor.Mask != 0 {
			n.Children[descriptor.CanonicalName] = node.New(descriptor.CanonicalName, true)
		}
	}
	return n
}
