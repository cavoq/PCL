package x509node

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509asn1"
)

// AddTimeEncoding adds the encoding facts of an ASN.1 time to target, the
// node holding the decoded time.
func AddTimeEncoding(target *node.Node, encoding x509asn1.TimeEncoding) {
	target.Children["encoding"] = node.New("encoding", encoding.Tag)
	target.Children["raw"] = node.New("raw", append([]byte(nil), encoding.RawDER...))
	target.Children["rawValue"] = node.New("rawValue", encoding.RawValue)
	target.Children["hasFraction"] = node.New("hasFraction", encoding.HasFraction)
	target.Children["hasSeconds"] = node.New("hasSeconds", encoding.HasSeconds)
	target.Children["hasZulu"] = node.New("hasZulu", encoding.HasZulu)
}
