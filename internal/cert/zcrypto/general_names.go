package zcrypto

import (
	"strconv"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509ext"
	nameprojector "github.com/cavoq/PCL/internal/zcrypto"
	"golang.org/x/crypto/cryptobyte"
)

type parsedGeneralName = x509ext.GeneralName

func generalNameType(tag int) string {
	return x509ext.GeneralNameType(tag)
}

func readGeneralName(input *cryptobyte.String) (parsedGeneralName, error) {
	return x509ext.ReadGeneralName(input)
}

func parseGeneralNames(value []byte) ([]parsedGeneralName, error) {
	return x509ext.DecodeGeneralNames(value)
}

func buildSubjectAltName(cert *x509.Certificate) *node.Node {
	return buildCertificateGeneralNames("subjectAltName", cert.Extensions, oid.SubjectAlternativeName)
}

func buildIssuerAltName(cert *x509.Certificate) *node.Node {
	return buildCertificateGeneralNames("issuerAltName", cert.Extensions, oid.IssuerAlternativeName)
}

func buildCertificateGeneralNames(
	name string,
	extensions []pkix.Extension,
	targetOID string,
) *node.Node {
	n := node.New(name, nil)
	extension, ok := findExtension(extensions, targetOID)
	if !ok {
		return n
	}

	names, err := parseGeneralNames(extension.Value)
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
		entry := nameprojector.BuildGeneralName(key, parsed)
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

		collectionName := generalNameType(parsed.Tag)
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
