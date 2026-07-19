package zcrypto

import (
	"errors"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
)

type reasonFlagDefinition struct {
	Bit      int
	NodeName string
}

// RFC 5280 ReasonFlags. These are DistributionPoint reasons, not the
// similarly named CRLReason ENUMERATED values used on revoked entries.
var reasonFlagDefinitions = [...]reasonFlagDefinition{
	{Bit: 0, NodeName: "unused"},
	{Bit: 1, NodeName: "keyCompromise"},
	{Bit: 2, NodeName: "cACompromise"},
	{Bit: 3, NodeName: "affiliationChanged"},
	{Bit: 4, NodeName: "superseded"},
	{Bit: 5, NodeName: "cessationOfOperation"},
	{Bit: 6, NodeName: "certificateHold"},
	{Bit: 7, NodeName: "privilegeWithdrawn"},
	{Bit: 8, NodeName: "aACompromise"},
}

type decodedReasonFlags struct {
	Raw        []byte
	Value      []byte
	UnusedBits int
	SetNames   []string
}

var errInvalidReasonFlags = errors.New("invalid ReasonFlags BIT STRING")

func decodeReasonFlags(encoded []byte) (decodedReasonFlags, error) {
	if len(encoded) == 1 {
		if encoded[0] != 0 {
			return decodedReasonFlags{}, errInvalidReasonFlags
		}
		return decodedReasonFlags{
			Raw:        append([]byte(nil), encoded...),
			UnusedBits: 0,
		}, nil
	}
	if len(encoded) < 2 || encoded[0] > 7 || encoded[len(encoded)-1]&byte((1<<encoded[0])-1) != 0 {
		return decodedReasonFlags{}, errInvalidReasonFlags
	}

	unusedBits := int(encoded[0])
	value := append([]byte(nil), encoded[1:]...)
	bitLength := len(value)*8 - unusedBits
	if bitLength > 9 || !reasonFlagSet(value, bitLength-1) {
		// ReasonFlags is a named-bit list. DER omits trailing zero bits, and
		// RFC 5280 defines no bits after aACompromise (bit 8).
		return decodedReasonFlags{}, errInvalidReasonFlags
	}

	decoded := decodedReasonFlags{
		Raw:        append([]byte(nil), encoded...),
		Value:      value,
		UnusedBits: unusedBits,
	}
	for _, definition := range reasonFlagDefinitions {
		if definition.Bit < bitLength && reasonFlagSet(value, definition.Bit) {
			decoded.SetNames = append(decoded.SetNames, definition.NodeName)
		}
	}
	return decoded, nil
}

func reasonFlagSet(value []byte, bit int) bool {
	byteIndex := bit / 8
	bitIndex := 7 - bit%8
	return byteIndex < len(value) && value[byteIndex]&(1<<bitIndex) != 0
}

func projectReasonFlags(decoded decodedReasonFlags) *node.Node {
	n := node.New("reasons", nil)
	n.Children["present"] = node.New("present", true)
	// Preserve the byte-slice representation exposed by the original parser.
	n.Children["raw"] = node.New("raw", cryptobyte.String(decoded.Raw))
	n.Children["unusedBits"] = node.New("unusedBits", decoded.UnusedBits)
	n.Children["value"] = node.New("value", cryptobyte.String(decoded.Value))
	for _, name := range decoded.SetNames {
		n.Children[name] = node.New(name, true)
	}
	return n
}
