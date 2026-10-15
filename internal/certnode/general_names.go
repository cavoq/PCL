package certnode

import (
	"strconv"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
)

func buildSubjectAltName(extensions x509ext.ExtensionIndex) *node.Node {
	return buildCertificateGeneralNames(
		"subjectAltName",
		extensions,
		oid.SubjectAlternativeName,
	)
}

func buildIssuerAltName(extensions x509ext.ExtensionIndex) *node.Node {
	return buildCertificateGeneralNames(
		"issuerAltName",
		extensions,
		oid.IssuerAlternativeName,
	)
}

func buildCertificateGeneralNames(
	name string,
	extensions x509ext.ExtensionIndex,
	targetOID string,
) *node.Node {
	n := node.New(name, nil)
	extension, ok := extensions.Lookup(targetOID).First()
	if !ok {
		return n
	}

	names, err := x509ext.DecodeGeneralNames(extension.Value)
	if err != nil {
		n.Children["raw"] = node.New("raw", append([]byte(nil), extension.Value...))
		n.Children["malformed"] = node.New("malformed", true)
		return n
	}

	n.Value = len(names)
	entries := node.New("entries", nil)
	n.Children["entries"] = entries
	typeCounts := make(map[int]int)
	for index, parsed := range names {
		key := strconv.Itoa(index)
		entry := x509node.BuildGeneralName(key, parsed)
		entries.Children[key] = entry

		// Preserve the established direct directoryName paths while the shared
		// GeneralName projection also retains its nested directoryName object.
		if directoryName := entry.Children["directoryName"]; directoryName != nil {
			for childName, child := range directoryName.Children {
				if childName != "raw" {
					entry.Children[childName] = child
				}
			}
		}

		collectionName := x509ext.GeneralNameType(parsed.Tag)
		collection := n.Children[collectionName]
		if collection == nil {
			collection = node.New(collectionName, nil)
			n.Children[collectionName] = collection
		}

		typeIndex := strconv.Itoa(typeCounts[parsed.Tag])
		collection.Children[typeIndex] = aliasGeneralNameNode(typeIndex, entry)
		typeCounts[parsed.Tag]++
	}

	return n
}

// aliasGeneralNameNode gives the per-type collection its compact numeric name
// while sharing the canonical entry's immutable value metadata and decoded
// children. This avoids parsing and copying every GeneralName twice.
func aliasGeneralNameNode(name string, canonical *node.Node) *node.Node {
	return &node.Node{
		Name:     name,
		Value:    canonical.Value,
		Children: canonical.Children,
	}
}
