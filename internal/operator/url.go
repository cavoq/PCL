package operator

import (
	"net/url"
	"strings"

	"github.com/cavoq/PCL/internal/node"
)

// HTTPURL checks an absolute ASCII HTTP(S) URL with a nonempty host. It
// checks syntax only; it does not resolve, fetch or establish ownership.
type HTTPURL struct{}

func (HTTPURL) Name() string { return "httpURL" }

func (HTTPURL) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	value, ok := n.Value.(string)
	if !ok {
		return false, nil
	}
	for _, c := range value {
		if c <= 0x20 || c >= 0x7f || strings.ContainsRune("<>\"{}|\\^`", c) {
			return false, nil
		}
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false, nil
	}
	return parsed.Opaque == "" && parsed.Hostname() != "" &&
		(strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")), nil
}
