package aia

import (
	"math/big"
	"testing"

	"github.com/cavoq/PCL/internal/testpki"
	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
)

// testSignedLeafPair returns a signed leaf (zcrypto), its real issuer, and a
// decoy with the same subject DN as the issuer but a different key.
func testSignedLeafPair(t *testing.T) (leaf, parent, decoy *zx509.Certificate) {
	t.Helper()
	issuer := testpki.Issue(t, "Issuing CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x0a, 0x0b}))
	decoy = testpki.Issue(t, "Issuing CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x0a, 0x0b})).Cert
	leaf = testpki.Issue(t, "leaf.example", issuer, testpki.Serial(2)).Cert
	return leaf, issuer.Cert, decoy
}

func TestSelectIssuer_signatureBeforeBundleOrder(t *testing.T) {
	leaf, parent, decoy := testSignedLeafPair(t)

	got, matched := SelectIssuer(leaf, []*zx509.Certificate{decoy, parent})
	if !matched || got != parent {
		t.Fatalf("SelectIssuer() = (%v, %v), want (%v, true)", got, matched, parent)
	}
}

func TestSelectIssuer_subjectDNWhenNoRawSignature(t *testing.T) {
	leaf, parent, _ := testSignedLeafPair(t)
	leafNoRaw := &zx509.Certificate{
		Issuer: leaf.Issuer,
	}
	got, matched := SelectIssuer(leafNoRaw, []*zx509.Certificate{parent})
	if !matched || got != parent {
		t.Fatalf("SelectIssuer() = (%v, %v), want (%v, true) via DN hint", got, matched, parent)
	}
}

func TestSelectIssuer_noFallbackWhenOnlyUnrelated(t *testing.T) {
	leaf, _, _ := testSignedLeafPair(t)
	unrelated := &zx509.Certificate{
		Subject:      zpkix.Name{CommonName: "Other CA"},
		SerialNumber: big.NewInt(3),
		IsCA:         true,
	}

	got, matched := SelectIssuer(leaf, []*zx509.Certificate{unrelated})
	if got != nil || matched {
		t.Fatalf("SelectIssuer() = (%v, %v), want (nil, false)", got, matched)
	}
}
