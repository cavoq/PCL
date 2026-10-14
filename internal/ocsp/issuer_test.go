package ocsp

import (
	"math/big"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/testpki"
	zx509 "github.com/zmap/zcrypto/x509"
	zx509pkix "github.com/zmap/zcrypto/x509/pkix"
)

func TestSigningIssuerFromPool_prefersSignature(t *testing.T) {
	ca := testpki.Issue(t, "CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x01}))
	// The spoof has the name, key identifier and key of the CA but is no CA.
	spoof := testpki.IssueWithKey(t, "CA", ca.Key, nil, testpki.Serial(2), testpki.SubjectKeyID([]byte{0x01})).Cert
	signer := testpki.Issue(t, "OCSP", ca, testpki.Serial(3), testpki.OCSPSigning(),
		testpki.SubjectKeyID([]byte{0x02})).Cert

	got := SigningIssuerFromPool(signer, []*zx509.Certificate{spoof, ca.Cert})
	if got != ca.Cert {
		t.Fatalf("SigningIssuerFromPool() = serial %v, want CA serial %v", got.SerialNumber, ca.Cert.SerialNumber)
	}
}

func TestBuildSignerEvalChain_usesTLSChainSuffix(t *testing.T) {
	rootCA := testpki.Issue(t, "Root", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x10}))
	intermediateCA := testpki.Issue(t, "Intermediate", rootCA, testpki.CA(), testpki.Serial(2),
		testpki.SubjectKeyID([]byte{0x11}))
	root, intermediate := rootCA.Cert, intermediateCA.Cert
	leaf := testpki.Issue(t, "Leaf", intermediateCA, testpki.Serial(3)).Cert
	ocspSigner := testpki.Issue(t, "OCSP", intermediateCA, testpki.Serial(4), testpki.OCSPSigning()).Cert

	tlsChain := []*cert.Info{
		{Cert: leaf, FilePath: "leaf.pem"},
		{Cert: intermediate, FilePath: "intermediate.pem"},
		{Cert: root, FilePath: "root.pem"},
	}
	signerInfo := &cert.Info{Cert: ocspSigner, FilePath: "ocsp.pem (signing cert)", Type: "ocspSigning"}

	got := BuildSignerEvalChain(ocspSigner, signerInfo, tlsChain, 0, 0, nil)
	if len(got) != 3 {
		t.Fatalf("BuildSignerEvalChain() len = %d, want 3", len(got))
	}
	if got[0].Cert != ocspSigner {
		t.Fatal("position 0 should be OCSP responder")
	}
	if got[1].Cert != intermediate || got[2].Cert != root {
		t.Fatalf("tail = %q -> %q, want intermediate -> root",
			got[1].Cert.Subject.CommonName, got[2].Cert.Subject.CommonName)
	}
	if got[0].Type != "ocspSigning" {
		t.Fatalf("signer type = %q, want ocspSigning", got[0].Type)
	}
	if got[1].Type != "intermediate" || got[2].Type != "root" {
		t.Fatalf("types = %q, %q", got[1].Type, got[2].Type)
	}
}

func TestBuildSignerEvalChain_resolvesViaAIA(t *testing.T) {
	parent := testpki.Issue(t, "OCSP CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x0a}))
	signer := testpki.Issue(t, "OCSP", parent, testpki.Serial(2), testpki.OCSPSigning(),
		testpki.IssuingCertificateURLs(testpki.Serve(t, parent.DER))).Cert

	got := BuildSignerEvalChain(signer, &cert.Info{Cert: signer, FilePath: "ocsp.pem"}, []*cert.Info{}, time.Second, 2, nil)
	if len(got) < 2 {
		t.Fatalf("BuildSignerEvalChain() len = %d, want responder + issuer", len(got))
	}
	if got[0].Cert != signer {
		t.Fatal("position 0 should be OCSP responder")
	}
	if got[1].Cert.Subject.CommonName != "OCSP CA" {
		t.Fatalf("issuer CN = %q, want OCSP CA", got[1].Cert.Subject.CommonName)
	}
}

func TestSigningIssuerFromPool_nilSigner(t *testing.T) {
	if got := SigningIssuerFromPool(nil, []*zx509.Certificate{{}}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestBuildSignerEvalChain_nilSignerReturnsTLSChain(t *testing.T) {
	tls := []*cert.Info{{Cert: &zx509.Certificate{SerialNumber: big.NewInt(1)}}}
	got := BuildSignerEvalChain(nil, &cert.Info{}, tls, 0, 0, nil)
	if len(got) != len(tls) {
		t.Fatalf("len = %d, want %d", len(got), len(tls))
	}
}

func TestCertMatchesSignerIssuer_subjectDN(t *testing.T) {
	signer := &zx509.Certificate{
		Issuer: zx509pkix.Name{CommonName: "Issuing CA"},
	}
	parent := &zx509.Certificate{
		Subject: zx509pkix.Name{CommonName: "Issuing CA"},
	}
	if !certMatchesSignerIssuer(signer, parent) {
		t.Fatal("expected issuer/subject DN match")
	}
	if certMatchesSignerIssuer(nil, parent) || certMatchesSignerIssuer(signer, nil) {
		t.Fatal("nil signer or candidate must not match")
	}
}

func TestCertMatchesSignerIssuer_akiOnly(t *testing.T) {
	signer := &zx509.Certificate{
		Issuer:         zx509pkix.Name{CommonName: "X"},
		AuthorityKeyId: []byte{0xab},
	}
	candidate := &zx509.Certificate{
		Subject:      zx509pkix.Name{CommonName: "Y"},
		SubjectKeyId: []byte{0xab},
	}
	if !certMatchesSignerIssuer(signer, candidate) {
		t.Fatal("expected AKI match")
	}
	if certMatchesSignerIssuer(signer, &zx509.Certificate{SubjectKeyId: []byte{0x00}}) {
		t.Fatal("expected no match")
	}
}

func TestResolveSignerIssuerPool_nilSigner(t *testing.T) {
	chain := []*cert.Info{{Cert: &zx509.Certificate{SerialNumber: big.NewInt(1)}}}
	pool := ResolveSignerIssuerPool(chain, nil, 0, 0, nil)
	if len(pool) != 1 {
		t.Fatalf("len = %d, want chain-only pool", len(pool))
	}
}

func TestResolveSignerIssuerPool_signerAlreadyInChain(t *testing.T) {
	ca := testpki.Issue(t, "CA", nil, testpki.CA(), testpki.SubjectKeyID([]byte{0x01}))
	signer := testpki.Issue(t, "OCSP", ca, testpki.Serial(2), testpki.OCSPSigning()).Cert
	tlsChain := []*cert.Info{{Cert: ca.Cert, FilePath: "ca.pem"}}
	pool := ResolveSignerIssuerPool(tlsChain, signer, 0, 0, nil)
	if len(pool) != 1 || pool[0] != ca.Cert {
		t.Fatalf("pool = %v, want unchanged chain pool", pool)
	}
}

func TestBuildSignerEvalChain_noIssuerReturnsResponderOnly(t *testing.T) {
	signer := testpki.Issue(t, "Orphan OCSP", nil, testpki.Serial(99), testpki.OCSPSigning()).Cert
	signerInfo := &cert.Info{Cert: signer, FilePath: "ocsp.pem", Type: "ocspSigning"}
	got := BuildSignerEvalChain(signer, signerInfo, nil, 0, 0, nil)
	if len(got) != 1 || got[0].Cert != signer {
		t.Fatalf("got %d entries, want responder only", len(got))
	}
}

func TestIndexInInfoChain_nilSerial(t *testing.T) {
	if _, ok := indexInInfoChain(&zx509.Certificate{SerialNumber: nil}, nil); ok {
		t.Fatal("nil serial should not match")
	}
}

func TestIndexInInfoChain_sameSerialDifferentIssuer(t *testing.T) {
	target := &zx509.Certificate{
		Issuer:                  zx509pkix.Name{CommonName: "Issuer A"},
		SerialNumber:            big.NewInt(7),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
	}
	unrelated := &zx509.Certificate{
		Issuer:                  zx509pkix.Name{CommonName: "Issuer B"},
		SerialNumber:            big.NewInt(7),
		RawSubjectPublicKeyInfo: []byte{0x30, 0x01},
	}
	match := &zx509.Certificate{
		Issuer:                  target.Issuer,
		SerialNumber:            new(big.Int).Set(target.SerialNumber),
		RawSubjectPublicKeyInfo: append([]byte(nil), target.RawSubjectPublicKeyInfo...),
	}
	chain := []*cert.Info{{Cert: unrelated}, {Cert: match}}
	if got, ok := indexInInfoChain(target, chain); !ok || got != 1 {
		t.Fatalf("indexInInfoChain() = (%d, %v), want (1, true)", got, ok)
	}
}

func TestInfoFromPoolCert_reusesTLSInfo(t *testing.T) {
	ca := &zx509.Certificate{SerialNumber: big.NewInt(7), Subject: zx509pkix.Name{CommonName: "CA"}}
	info := &cert.Info{Cert: ca, FilePath: "trusted.pem"}
	got := infoFromPoolCert(ca, []*cert.Info{info})
	if got != info {
		t.Fatalf("infoFromPoolCert() should reuse chain Info, got %p want %p", got, info)
	}
	if infoFromPoolCert(nil, nil) != nil {
		t.Fatal("nil cert should return nil")
	}
}
