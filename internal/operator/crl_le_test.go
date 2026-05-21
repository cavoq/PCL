package operator

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/crl"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func readLEFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "crl", "testdata", "letsencrypt", name))
	if err != nil {
		t.Fatalf("read LE fixture %s: %v", name, err)
	}
	return data
}

func loadLetsEncryptRootX1CRL(t *testing.T) *x509.RevocationList {
	t.Helper()
	revocationList, err := crl.ParseCRL(readLEFixture(t, "isrg-root-x1.crl"))
	if err != nil {
		t.Fatalf("parse LE root CRL: %v", err)
	}
	return revocationList
}

func loadLetsEncryptRootX1Cert(t *testing.T) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(readLEFixture(t, "isrgrootx1.der"))
	if err != nil {
		t.Fatalf("parse LE root cert: %v", err)
	}
	return c
}

// TestCRLSignedBy_LERoot_verifiesWithOfficialRoot ensures the operator checks
// signatures after CertSignsCRL identity hints.
func TestCRLSignedBy_LERoot_verifiesWithOfficialRoot(t *testing.T) {
	revocationList := loadLetsEncryptRootX1CRL(t)
	root := loadLetsEncryptRootX1Cert(t)

	ctx := &EvaluationContext{
		CRLs:  []*crl.Info{{CRL: revocationList}},
		Chain: []*cert.Info{{Cert: root}},
	}
	op := CRLSignedBy{}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected pass when official ISRG Root X1 is in chain and signature verifies")
	}
}

// TestCRLSignedBy_LERoot_impostorThenRoot_passes when the real ISRG Root X1 is
// later in chain than a DN-only impostor (signature-first selection).
func TestCRLSignedBy_LERoot_impostorThenRoot_passes(t *testing.T) {
	revocationList := loadLetsEncryptRootX1CRL(t)
	root := loadLetsEncryptRootX1Cert(t)

	impostor := &x509.Certificate{
		Subject:      revocationList.Issuer,
		SubjectKeyId: revocationList.AuthorityKeyId,
		IsCA:         true,
		SerialNumber: big.NewInt(99),
	}

	ctx := &EvaluationContext{
		CRLs: []*crl.Info{{CRL: revocationList}},
		Chain: []*cert.Info{
			{Cert: impostor},
			{Cert: root},
		},
	}
	op := CRLSignedBy{}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected pass: must use signature-verified root, not first DN match")
	}
}

// TestCRLSignedBy_LERoot_impostorOnly_fails when chain has no cert that verifies.
func TestCRLSignedBy_LERoot_impostorOnly_fails(t *testing.T) {
	revocationList := loadLetsEncryptRootX1CRL(t)
	impostor := &x509.Certificate{
		Subject:      revocationList.Issuer,
		SubjectKeyId: revocationList.AuthorityKeyId,
		IsCA:         true,
		SerialNumber: big.NewInt(99),
	}

	ctx := &EvaluationContext{
		CRLs:  []*crl.Info{{CRL: revocationList}},
		Chain: []*cert.Info{{Cert: impostor}},
	}
	op := CRLSignedBy{}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected fail when no chain member verifies CRL signature")
	}
}

// TestCRLSignedBy_LERoot_noMatchingChainMemberIsNotApplicable when the CRL
// issuer is not represented in the chain, the operator treats the CRL as N/A.
func TestCRLSignedBy_LERoot_noMatchingChainMemberIsNotApplicable(t *testing.T) {
	revocationList := loadLetsEncryptRootX1CRL(t)
	unrelated := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Unrelated CA"},
		SerialNumber: big.NewInt(1),
		IsCA:         true,
	}

	ctx := &EvaluationContext{
		CRLs:  []*crl.Info{{CRL: revocationList}},
		Chain: []*cert.Info{{Cert: unrelated}},
	}
	op := CRLSignedBy{}
	got, err := op.Evaluate(nil, ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected pass (skip) when chain has no CRL signer candidate")
	}
}
