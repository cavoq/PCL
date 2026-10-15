package certnode

import "github.com/cavoq/PCL/internal/node"

func malformedExtensionNodeWithRaw(name string, raw []byte) *node.Node {
	n := node.New(name, nil)
	n.Children["malformed"] = node.New("malformed", true)
	n.Children["raw"] = node.New("raw", append([]byte(nil), raw...))
	return n
}
