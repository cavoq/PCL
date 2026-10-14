package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/rand/v2"
	"testing"

	"github.com/cavoq/PCL/internal/testpki"
)

// issueTestCertificate issues a certificate for subject signed by issuer, or
// self-signed when issuer is nil.
func issueTestCertificate(t *testing.T, subject string, isCA bool, issuer *testpki.Certificate) (*Info, *testpki.Certificate) {
	t.Helper()
	options := []testpki.Option{testpki.Serial(rand.Int64()), testpki.Mutate(func(template *x509.Certificate) {
		template.BasicConstraintsValid = true
	})}
	if isCA {
		options = append(options, testpki.CA())
	}
	issued := testpki.IssueWithKey(t, subject, testpki.ECDSAKey(t), issuer, options...)
	return &Info{Cert: issued.Cert, FilePath: subject}, issued
}

func TestBuildChainForStartsOnlyAtTargets(t *testing.T) {
	root, rootIssuer := issueTestCertificate(t, "Root", true, nil)
	intermediate, intermediateIssuer := issueTestCertificate(t, "Intermediate", true, rootIssuer)
	otherLeaf, _ := issueTestCertificate(t, "Other Leaf", false, intermediateIssuer)
	orphan, _ := issueTestCertificate(t, "Orphan", false, &testpki.Certificate{
		Std: &x509.Certificate{Subject: pkix.Name{CommonName: "Unknown CA"}},
		Key: intermediateIssuer.Key,
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
