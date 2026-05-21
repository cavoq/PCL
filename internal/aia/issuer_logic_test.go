package aia

import (
	"testing"

	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
)

// TestSelectIssuer_LEAIA_noMatchReturnsNil documents that unrelated LE-style
// backup intermediates in a CA Issuers bundle must not be used as parent.
func TestSelectIssuer_LEAIA_noMatchReturnsNil(t *testing.T) {
	child := &zx509.Certificate{
		Issuer: zpkix.Name{
			Organization: []string{"Internet Security Research Group"},
			CommonName:   "ISRG Root X1",
			Country:      []string{"US"},
		},
	}
	backupIntermediate := &zx509.Certificate{
		Subject: zpkix.Name{CommonName: "Let's Encrypt E9"},
	}
	otherIntermediate := &zx509.Certificate{
		Subject: zpkix.Name{CommonName: "Let's Encrypt R14"},
	}

	got, matched := SelectIssuer(child, []*zx509.Certificate{backupIntermediate, otherIntermediate})
	if got != nil || matched {
		t.Fatalf("SelectIssuer() = (%v, %v), want (nil, false)", got, matched)
	}
}
