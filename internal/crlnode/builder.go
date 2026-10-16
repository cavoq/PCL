// Package crlnode projects CRLs into node trees.
package crlnode

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/x509asn1"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
)

type CRLBuilder struct{}

func NewCRLBuilder() *CRLBuilder {
	return &CRLBuilder{}
}

func (b *CRLBuilder) Build(crl *x509.RevocationList) *node.Node {
	return buildCRL(crl)
}

func BuildTree(crl *x509.RevocationList) *node.Node {
	return NewCRLBuilder().Build(crl)
}

func buildCRL(crl *x509.RevocationList) *node.Node {
	root := node.New("crl", nil)

	root.Children["issuer"] = x509node.BuildName("issuer", crl.RawIssuer, crl.Issuer)
	root.Children["thisUpdate"] = node.New("thisUpdate", crl.ThisUpdate)
	if !crl.NextUpdate.IsZero() {
		root.Children["nextUpdate"] = node.New("nextUpdate", crl.NextUpdate)
	}
	root.Children["signatureAlgorithm"] = buildSignatureAlgorithm(crl)
	root.Children["tbsSignatureAlgorithm"] = buildTBSSignatureAlgorithm(crl)

	if len(crl.RevokedCertificates) > 0 {
		root.Children["revokedCertificates"] = buildRevokedCertificates(crl.RevokedCertificates)
	}
	projectTBSCertListMetadata(root, crl.RawTBSRevocationList)

	if len(crl.Extensions) > 0 {
		root.Children["extensions"] = x509node.BuildExtensions(crl.Extensions)
		projectCRLExtensions(root, crl.Extensions)
	} else {
		// Preserve compatibility for manually constructed values that contain
		// semantic fields but no raw extension list.
		if crl.Number != nil {
			root.Children["crlNumber"] = node.New("crlNumber", crl.Number.String())
		}
		if keyIdentifier := x509ext.AuthorityKeyIdentifier(crl); len(keyIdentifier) > 0 {
			root.Children["authorityKeyIdentifier"] = node.New("authorityKeyIdentifier", keyIdentifier)
		}
	}

	if len(crl.Signature) > 0 {
		root.Children["signatureValue"] = node.New("signatureValue", crl.Signature)
	}

	return root
}

func projectCRLExtensions(root *node.Node, extensions []pkix.Extension) {
	extensionsNode := root.Children["extensions"]
	seen := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		identifier := extension.Id.String()
		if _, duplicate := seen[identifier]; duplicate {
			continue
		}
		seen[identifier] = struct{}{}
		projected, err := projectCRLExtension(extension)
		if projected == nil && err == nil {
			continue
		}
		extensionNode := extensionsNode.Children[identifier]
		if err != nil {
			extensionNode.Children["malformed"] = node.New("malformed", true)
			continue
		}
		graftProjection(extensionNode, projected)

		switch identifier {
		case oid.AuthorityKeyIdentifier:
			if keyIdentifier := projected.Children["keyIdentifier"]; keyIdentifier != nil {
				if value, ok := keyIdentifier.Value.([]byte); ok {
					root.Children["authorityKeyIdentifier"] = node.New(
						"authorityKeyIdentifier",
						append([]byte(nil), value...),
					)
				}
			}
		case oid.CRLNumber:
			// Preserve the established root scalar (decimal string) while the
			// extension node exposes the lossless typed integer metadata.
			decimal := projected.Children["decimal"]
			if decimal != nil {
				root.Children["crlNumber"] = node.New("crlNumber", decimal.Value)
			}
		case oid.DeltaCRLIndicator:
			root.Children["deltaCRLIndicator"] = projected
		case oid.IssuingDistributionPoint:
			root.Children["issuingDistributionPoint"] = projected
		case oid.FreshestCRL:
			root.Children["freshestCRL"] = projected
		}
	}
}

func graftProjection(extension, projected *node.Node) {
	if extension == nil || projected == nil {
		return
	}
	if rawValue := extension.Children["value"]; rawValue != nil {
		extension.Children["rawValue"] = node.New("rawValue", rawValue.Value)
	}
	for name, child := range projected.Children {
		extension.Children[name] = child
	}
}

func buildSignatureAlgorithm(crl *x509.RevocationList) *node.Node {
	params := x509asn1.ParseSignedObjectAlgorithmParams(crl.Raw)
	return x509node.BuildAlgorithmIdentifier("signatureAlgorithm", crl.SignatureAlgorithm.String(), params)
}

func buildTBSSignatureAlgorithm(crl *x509.RevocationList) *node.Node {
	params := parseTBSCRLSignatureParams(crl.RawTBSRevocationList)
	return x509node.BuildAlgorithmIdentifier("tbsSignatureAlgorithm", crl.SignatureAlgorithm.String(), params)
}

func buildRevokedCertificates(revoked []x509.RevokedCertificate) *node.Node {
	n := node.New("revokedCertificates", len(revoked))

	for i, rc := range revoked {
		rcNode := node.New(fmt.Sprintf("%d", i), nil)
		if len(rc.Raw) > 0 {
			rcNode.Children["raw"] = node.New("raw", append([]byte(nil), rc.Raw...))
		}
		if rc.SerialNumber != nil {
			rcNode.Children["serialNumber"] = node.New("serialNumber", rc.SerialNumber.String())
		}
		rcNode.Children["revocationDate"] = node.New("revocationDate", rc.RevocationTime)

		if len(rc.Extensions) > 0 {
			extsNode := x509node.BuildExtensions(rc.Extensions)
			seen := make(map[string]struct{}, len(rc.Extensions))
			for _, extension := range rc.Extensions {
				identifier := extension.Id.String()
				if _, duplicate := seen[identifier]; duplicate {
					continue
				}
				seen[identifier] = struct{}{}
				projected, err := projectEntryExtension(extension)
				if projected == nil && err == nil {
					continue
				}
				extensionNode := extsNode.Children[identifier]
				if err != nil {
					extensionNode.Children["malformed"] = node.New("malformed", true)
					continue
				}
				graftProjection(extensionNode, projected)
			}
			rcNode.Children["extensions"] = extsNode
		}

		n.Children[fmt.Sprintf("%d", i)] = rcNode
	}

	return n
}
