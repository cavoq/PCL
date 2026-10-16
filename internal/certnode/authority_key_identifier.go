package certnode

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/cavoq/PCL/internal/x509node"
	"github.com/zmap/zcrypto/x509/pkix"
)

// ParseAuthorityKeyIdentifierStrict decodes, validates, and projects exactly
// one AuthorityKeyIdentifier value as defined by RFC 5280 section 4.2.1.1.
func ParseAuthorityKeyIdentifierStrict(extValue []byte) (*node.Node, error) {
	facts, err := x509ext.DecodeAuthorityKeyIdentifierExtension(pkix.Extension{Value: extValue})
	if err != nil {
		return nil, err
	}
	return x509node.ProjectAuthorityKeyIdentifier(facts), nil
}
