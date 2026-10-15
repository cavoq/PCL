package x509node

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

// CriticalExtensionsProcessable reports whether every critical extension at
// location has one unique, well-formed representation and is registered as
// processed there. The signed-object adapters remain responsible for adding
// malformed and unprocessed markers to the shared extension projection.
func CriticalExtensionsProcessable(n *node.Node, location oid.ExtensionLocation) bool {
	if n == nil {
		return false
	}
	extensions, _ := n.Resolve("extensions")
	if extensions == nil {
		return true
	}
	if extensions.Children["duplicateOIDs"] != nil {
		return false
	}

	seen := make(map[*node.Node]struct{}, len(extensions.Children))
	for _, extension := range extensions.Children {
		if extension == nil {
			continue
		}
		if _, duplicate := seen[extension]; duplicate {
			continue
		}
		seen[extension] = struct{}{}

		criticalNode, _ := extension.Resolve("critical")
		if criticalNode == nil {
			continue
		}
		critical, ok := criticalNode.Value.(bool)
		if !ok {
			return false
		}
		if !critical {
			continue
		}
		if extension.Children["malformed"] != nil {
			return false
		}
		if unprocessed := extension.Children["unprocessed"]; unprocessed != nil {
			value, ok := unprocessed.Value.(bool)
			if !ok || value {
				return false
			}
		}

		oidNode, _ := extension.Resolve("oid")
		if oidNode == nil {
			return false
		}
		identifier, ok := oidNode.Value.(string)
		if !ok || !oid.ExtensionProcessableAt(identifier, location) {
			return false
		}
	}
	return true
}
