// Package zcrypto provides zcrypto conversion helpers.
package zcrypto

import (
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"

	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

func ToStdCert(cert *zx509.Certificate) (*stdx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return stdx509.ParseCertificate(cert.Raw)
}

func FromStdCert(cert *stdx509.Certificate) (*zx509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	return zx509.ParseCertificate(cert.Raw)
}

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

	for _, ext := range extensions {
		oidStr := ext.oid
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
