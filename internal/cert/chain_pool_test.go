package cert

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/testpki"
	zx509 "github.com/zmap/zcrypto/x509"
)

func TestClimbChainWithPool_usesPoolWhenNoCaIssuers(t *testing.T) {
	// Certificate serial numbers are issuer-scoped. Sharing the leaf's serial
	// exercises identity-safe pool cycle detection.
	parent := testpki.Issue(t, "Pool Parent CA", nil, testpki.CA(), testpki.Serial(3),
		testpki.SubjectKeyID([]byte{0x01, 0x02}))
	// No CA Issuers location, so the climb must use the pool.
	intermediate := testpki.Issue(t, "No AIA Intermediate", parent, testpki.CA(), testpki.Serial(2),
		testpki.SubjectKeyID([]byte{0x03, 0x04}))
	leaf := testpki.Issue(t, "sub.example", intermediate, testpki.Serial(3))
	parentInfo := &Info{Cert: parent.Cert, FilePath: "/trusted/parent.pem"}
	interInfo := &Info{Cert: intermediate.Cert, FilePath: "intermediate.cer"}
	leafInfo := &Info{Cert: leaf.Cert, FilePath: "leaf.pem"}

	pool := []*Info{parentInfo}
	got := ClimbChainWithPool([]*Info{leafInfo, interInfo}, pool, time.Second, 2, nil)
	if len(got) != 3 {
		t.Fatalf("got %d certs, want leaf + intermediate + pool parent", len(got))
	}
	if got[2].Cert.Subject.CommonName != "Pool Parent CA" {
		t.Fatalf("parent CN = %q", got[2].Cert.Subject.CommonName)
	}
	if got[2].FilePath != "/trusted/parent.pem" {
		t.Fatalf("parent path = %q", got[2].FilePath)
	}
}

func TestClimbChainWithPool_doesNotUseDNOnlyPoolMatch(t *testing.T) {
	impostor := testpki.Issue(t, "Wrong Parent", nil, testpki.CA(), testpki.Serial(99))
	child := testpki.Issue(t, "child", impostor).Cert
	// The pool holds an unrelated CA that does not sign child.
	realParent := testpki.Issue(t, "Real Parent", nil, testpki.CA(), testpki.Serial(2)).Cert

	child.Issuer = realParent.Subject // DN matches real parent but signed by impostor
	pool := []*Info{{Cert: realParent, FilePath: "real.pem"}}

	got := ClimbChainWithPool([]*Info{{Cert: child, FilePath: "child.pem"}}, pool, time.Second, 1, nil)
	if len(got) != 1 {
		t.Fatalf("got %d certs, want 1 (no DN-only pool link)", len(got))
	}
}

func TestClimbChainWithPool_maxDepthZero(t *testing.T) {
	leaf := &Info{Cert: &zx509.Certificate{SerialNumber: big.NewInt(1)}}
	got := ClimbChainWithPool([]*Info{leaf}, nil, time.Second, 0, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want unchanged chain", len(got))
	}
}

func TestClimbChainWithPool_emitsWarningOnFetchFailure(t *testing.T) {
	parent := testpki.Issue(t, "Parent CA", nil, testpki.CA())
	childZ := testpki.Issue(t, "child", parent, testpki.Serial(2),
		testpki.IssuingCertificateURLs("http://127.0.0.1:1/unreachable")).Cert
	var buf bytes.Buffer
	got := ClimbChainWithPool([]*Info{{Cert: childZ, FilePath: "child.pem"}}, nil, 50*time.Millisecond, 2, &buf)
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if buf.Len() == 0 {
		t.Fatal("expected warning when CA Issuers fetch fails")
	}
}
