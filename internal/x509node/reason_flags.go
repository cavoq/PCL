package x509node

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

// BuildReasonFlags projects a decoded ReasonFlags BIT STRING. Certificate and
// CRL trees share this shape: the node value is the reason mask and every
// defined flag is an explicit boolean, so policies can test a flag with eq
// true or eq false. Whether the optional field was encoded at all is shown by
// the node's presence (and hasReasons on distribution points).
func BuildReasonFlags(name string, reasons *x509ext.ReasonFlags) *node.Node {
	n := node.New(name, uint16(reasons.Mask))
	n.Children["present"] = node.New("present", true)
	n.Children["raw"] = node.New("raw", append([]byte(nil), reasons.RawDER...))
	n.Children["value"] = node.New("value", append([]byte(nil), reasons.Value...))
	n.Children["unusedBits"] = node.New("unusedBits", reasons.UnusedBits)
	for _, descriptor := range x509ext.ReasonFlagDescriptors() {
		n.Children[descriptor.CanonicalName] = node.New(
			descriptor.CanonicalName,
			reasons.Mask&descriptor.Mask != 0,
		)
	}
	return n
}
