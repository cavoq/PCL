package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	cryptopkix "crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
)

type testIssuer struct {
	template *cryptox509.Certificate
	key      *ecdsa.PrivateKey
}

// issueTestCertificate creates a certificate for subject signed by issuer, or
// self-signed when issuer is nil, and returns it with its signing identity.
func issueTestCertificate(t *testing.T, subject string, isCA bool, issuer *testIssuer) (*Info, *testIssuer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          serial,
		Subject:               cryptopkix.Name{CommonName: subject},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage = cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign
	}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.template, issuer.key
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Info{Cert: parsed, FilePath: subject}, &testIssuer{template: template, key: key}
}

func TestBuildChainForStartsOnlyAtTargets(t *testing.T) {
	root, rootIssuer := issueTestCertificate(t, "Root", true, nil)
	intermediate, intermediateIssuer := issueTestCertificate(t, "Intermediate", true, rootIssuer)
	otherLeaf, _ := issueTestCertificate(t, "Other Leaf", false, intermediateIssuer)
	orphan, _ := issueTestCertificate(t, "Orphan", false, &testIssuer{
		template: &cryptox509.Certificate{Subject: cryptopkix.Name{CommonName: "Unknown CA"}},
		key:      intermediateIssuer.key,
	})

	chain, err := BuildChainFor([]*Info{orphan}, []*Info{orphan, otherLeaf, intermediate, root})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || chain[0] != orphan {
		t.Fatalf("chain = %v, want only the target whose issuer is missing", chainPaths(chain))
	}
}

func TestBuildChainForPrefersTheIssuerThatSigned(t *testing.T) {
	root, rootIssuer := issueTestCertificate(t, "Root", true, nil)
	oldCA, _ := issueTestCertificate(t, "Rollover CA", true, rootIssuer)
	newCA, newIssuer := issueTestCertificate(t, "Rollover CA", true, rootIssuer)
	leaf, _ := issueTestCertificate(t, "Leaf", false, newIssuer)

	chain, err := BuildChainFor([]*Info{leaf}, []*Info{leaf, oldCA, newCA, root})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 || chain[1] != newCA || chain[2] != root {
		t.Fatalf("chain = %v, want leaf, the signing CA and the root", chainPaths(chain))
	}
}

func TestSelfIssuedIsNotSelfSigned(t *testing.T) {
	_, rootIssuer := issueTestCertificate(t, "Root", true, nil)
	// A self-issued certificate for the root name, signed by the root's key
	// but carrying a new key, as in a key rollover.
	rollover, _ := issueTestCertificate(t, "Root", true, rootIssuer)
	root, _ := issueTestCertificate(t, "Standalone Root", true, nil)

	if !IsSelfIssued(rollover.Cert) || IsSelfSigned(rollover.Cert) {
		t.Fatal("a rollover certificate is self-issued but not self-signed")
	}
	if !IsSelfSigned(root.Cert) || GetCertType(root.Cert) != TypeRoot {
		t.Fatal("a self-signed CA certificate is a root")
	}
	if GetCertType(rollover.Cert) != TypeIntermediate {
		t.Fatalf("rollover type = %s, want intermediate", GetCertType(rollover.Cert))
	}
}

func TestCheckSignatureFromRequiresACAIssuer(t *testing.T) {
	_, rootIssuer := issueTestCertificate(t, "Root", true, nil)
	notCA, notCAIssuer := issueTestCertificate(t, "Not A CA", false, rootIssuer)
	leaf, _ := issueTestCertificate(t, "Leaf", false, notCAIssuer)
	if err := CheckSignatureFrom(leaf.Cert, notCA.Cert); err == nil {
		t.Fatal("a certificate issued by a non-CA must not verify")
	}
	if !SignedBy(leaf.Cert, notCA.Cert) {
		t.Fatal("SignedBy checks the signature only")
	}
}

func chainPaths(chain []*Info) []string {
	paths := make([]string, len(chain))
	for index, info := range chain {
		paths[index] = info.FilePath
	}
	return paths
}
