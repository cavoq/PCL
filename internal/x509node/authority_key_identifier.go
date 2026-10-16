package x509node

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
)

// ProjectAuthorityKeyIdentifier projects a strictly decoded
// AuthorityKeyIdentifier for certificates and CRLs alike. Absent fields have
// no node, so rules can require or forbid each one with present/absent.
func ProjectAuthorityKeyIdentifier(facts *x509ext.AuthorityKeyIdentifierFacts) *node.Node {
	n := node.New("authorityKeyIdentifier", nil)
	n.Children["raw"] = node.New("raw", append([]byte(nil), facts.RawDER...))
	if facts.KeyIdentifier != nil {
		n.Children["keyIdentifier"] = node.New(
			"keyIdentifier",
			append([]byte(nil), facts.KeyIdentifier...),
		)
	}
	if facts.AuthorityIssuer != nil {
		issuer := node.New("authorityCertIssuer", nil)
		AddGeneralNames(issuer, facts.AuthorityIssuer)
		issuer.Children["count"] = node.New("count", len(facts.AuthorityIssuer))
		n.Children["authorityCertIssuer"] = issuer
	}
	if facts.SerialNumber != nil {
		serial := node.New("authorityCertSerialNumber", facts.SerialNumber.Scalar())
		serial.Children["decimal"] = node.New("decimal", facts.SerialNumber.Decimal)
		serial.Children["fitsInt"] = node.New("fitsInt", facts.SerialNumber.FitsInt)
		n.Children["authorityCertSerialNumber"] = serial
	}
	return n
}
