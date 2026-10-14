package operator

import (
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/node"
)

// IsIA5String checks if a string value uses IA5String encoding (ASCII).
// IA5String is equivalent to ASCII (characters 0x00-0x7F).
type IsIA5String struct{}

func (IsIA5String) Name() string { return "isIA5String" }

func (IsIA5String) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	return hasEncodingTag(n, cryptobyte_asn1.IA5String), nil
}

// IsPrintableString checks if a string value uses PrintableString encoding.
// PrintableString allows limited character set: A-Z, a-z, 0-9, space, and specific special chars.
type IsPrintableString struct{}

func (IsPrintableString) Name() string { return "isPrintableString" }

func (IsPrintableString) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	return hasEncodingTag(n, cryptobyte_asn1.PrintableString), nil
}

// IsUTF8String checks if a string value uses UTF8String encoding.
type IsUTF8String struct{}

func (IsUTF8String) Name() string { return "isUTF8String" }

func (IsUTF8String) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	return hasEncodingTag(n, cryptobyte_asn1.UTF8String), nil
}

// ValidIA5String checks that a string contains only valid IA5String characters.
// IA5String = ASCII (0x00-0x7F).
// Collection traversal belongs to the Every operator.
type ValidIA5String struct{}

func (ValidIA5String) Name() string { return "validIA5String" }

func (ValidIA5String) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}
	return isASCII(str), nil
}

// ValidPrintableString checks that a string contains only valid PrintableString characters.
// If the node has children (array-like), checks all children.
type ValidPrintableString struct{}

func (ValidPrintableString) Name() string { return "validPrintableString" }

func (ValidPrintableString) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// If node has value, check it directly
	if n.Value != nil {
		str, ok := n.Value.(string)
		if !ok {
			return false, nil
		}
		return isPrintableStringCompatible(str), nil
	}

	// If node has children (array-like), check all children
	if len(n.Children) > 0 {
		for _, child := range n.Children {
			if child.Value == nil {
				continue
			}
			str, ok := child.Value.(string)
			if !ok {
				return false, nil
			}
			if !isPrintableStringCompatible(str) {
				return false, nil
			}
		}
		return true, nil
	}

	return false, nil
}

// Helper functions

// hasEncodingTag reports whether n carries the DN attribute encoding child
// with the given universal string tag.
func hasEncodingTag(n *node.Node, tag cryptobyte_asn1.Tag) bool {
	if n == nil {
		return false
	}
	encodingNode := n.Children["encoding"]
	if encodingNode == nil {
		return false
	}
	value, ok := encodingNode.Value.(int)
	return ok && value == int(tag)
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > 0x7F {
			return false
		}
	}
	return true
}

func isPrintableStringCompatible(s string) bool {
	for _, c := range s {
		if !isPrintableChar(c) {
			return false
		}
	}
	return true
}

func isPrintableChar(c rune) bool {
	// Upper case letters
	if c >= 'A' && c <= 'Z' {
		return true
	}
	// Lower case letters
	if c >= 'a' && c <= 'z' {
		return true
	}
	// Digits
	if c >= '0' && c <= '9' {
		return true
	}
	// Special characters allowed in PrintableString per ASN.1
	switch c {
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
		return true
	}
	return false
}
