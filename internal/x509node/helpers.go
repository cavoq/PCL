// Package x509node projects X.509 structures (names, extensions, algorithm
// identifiers, general names) into node trees shared by the certificate, CRL
// and OCSP builders.
package x509node

import (
	stdpkix "crypto/x509/pkix"

	zpkix "github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

type extensionFacts struct {
	oid      string
	critical bool
	value    []byte
}

func BuildExtensions(extensions []zpkix.Extension) *node.Node {
	facts := make([]extensionFacts, 0, len(extensions))
	for _, extension := range extensions {
		facts = append(facts, extensionFacts{
			oid:      extension.Id.String(),
			critical: extension.Critical,
			value:    extension.Value,
		})
	}
	return buildExtensions(facts)
}

// BuildStandardExtensions projects extensions from Go's standard x509 types
// into the same representation used for zcrypto certificate and CRL inputs.
func BuildStandardExtensions(extensions []stdpkix.Extension) *node.Node {
	facts := make([]extensionFacts, 0, len(extensions))
	for _, extension := range extensions {
		facts = append(facts, extensionFacts{
			oid:      extension.Id.String(),
			critical: extension.Critical,
			value:    extension.Value,
		})
	}
	return buildExtensions(facts)
}

func buildExtensions(extensions []extensionFacts) *node.Node {
	n := node.New("extensions", nil)
	seenOIDs := make(map[string]struct{}, len(extensions))

	for _, ext := range extensions {
		oidStr := ext.oid
		if _, duplicate := seenOIDs[oidStr]; duplicate {
			duplicates := n.Children["duplicateOIDs"]
			if duplicates == nil {
				duplicates = node.New("duplicateOIDs", nil)
				n.Children["duplicateOIDs"] = duplicates
			}
			duplicates.AddElement(node.New("oid", oidStr))
			continue
		}
		seenOIDs[oidStr] = struct{}{}

		extNode := node.New(oidStr, nil)
		extNode.Children["oid"] = node.New("oid", oidStr)
		extNode.Children["critical"] = node.New("critical", ext.critical)
		extNode.Children["value"] = node.New("value", ext.value)

		// Add friendly name if available
		if name, ok := oid.ExtensionName(oidStr); ok {
			extNode.Children["name"] = node.New("name", name)
			// Also add the extension under its friendly name for easier access
			n.Children[name] = extNode
		}

		// Always add under OID
		n.Children[oidStr] = extNode
	}

	return n
}
