package operator

import (
	"bytes"

	"github.com/cavoq/PCL/internal/node"
)

// UTF8NoBOM validates that a UTF-8 string does not start with a Byte Order Mark (BOM).
// The UTF-8 BOM is the byte sequence 0xEF 0xBB 0xBF.
// This is useful for validating UTF8String fields per RFC 3629 and RFC 9598.
//
// Per RFC 3629: "The UTF-8 BOM is not recommended for use in UTF-8 encoded strings"
// Per RFC 9598 3: "The UTF8String encoding MUST NOT contain a Byte Order Mark (BOM)"
//
// Example: validate SmtpUTF8Mailbox doesn't contain BOM
//   target: certificate.subjectAltName.otherName.smtpUTF8Mailbox
//   operator: utf8NoBom
type UTF8NoBOM struct{}

func (UTF8NoBOM) Name() string { return "utf8NoBom" }

func (UTF8NoBOM) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// UTF-8 BOM byte sequence: EF BB BF
	utf8BOM := []byte{0xEF, 0xBB, 0xBF}

	switch v := n.Value.(type) {
	case string:
		// Check if string starts with BOM (when encoded as UTF-8)
		return !bytes.HasPrefix([]byte(v), utf8BOM), nil
	case []byte:
		return !bytes.HasPrefix(v, utf8BOM), nil
	default:
		// Non-string/bytes values cannot have BOM
		return true, nil
	}
}

// ContainsBOM validates that a UTF-8 string DOES start with a Byte Order Mark.
// This is the inverse of UTF8NoBOM, useful for detecting problematic BOM presence.
type ContainsBOM struct{}

func (ContainsBOM) Name() string { return "containsBom" }

func (ContainsBOM) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	noBom, err := UTF8NoBOM{}.Evaluate(n, ctx, operands)
	if err != nil {
		return false, err
	}
	return !noBom, nil
}