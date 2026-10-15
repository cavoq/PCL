package crlnode

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/crl"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func readCRLFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "crl", "testdata", "test.crl"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildTreeWithChain_nilCRL(t *testing.T) {
	if got := BuildTreeWithChain(nil, nil); got != nil {
		t.Fatalf("BuildTreeWithChain(nil) = %v, want nil", got)
	}
}

func TestBuildTreeWithChain_isCACRLFromCASigner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "CA Signer"},
		SubjectKeyId: []byte{0x0b},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	}
	revocationList := &x509.RevocationList{
		Issuer:         pkix.Name{CommonName: "CA Signer"},
		AuthorityKeyId: []byte{0x0b},
		ThisUpdate:     now,
		NextUpdate:     now.Add(7 * 24 * time.Hour),
	}

	tree := BuildTreeWithChain(revocationList, []*x509.Certificate{signer})
	if tree == nil {
		t.Fatal("expected CRL tree")
	}
	isCA, ok := tree.Children["isCACRL"]
	if !ok {
		t.Fatal("isCACRL node missing")
	}
	if isCA.Value != true {
		t.Fatalf("isCACRL = %v, want true", isCA.Value)
	}
}

func TestBuildTreeWithChain_isCACRLFalseForShortValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	revocationList := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown"},
		ThisUpdate: now,
		NextUpdate: now.Add(5 * 24 * time.Hour),
	}

	tree := BuildTreeWithChain(revocationList, nil)
	isCA := tree.Children["isCACRL"]
	if isCA.Value != false {
		t.Fatalf("isCACRL = %v, want false", isCA.Value)
	}
}

func TestBuildTree_setsNodes(t *testing.T) {
	revocationList, err := crl.ParseCRL(readCRLFixture(t))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	tree := BuildTree(revocationList)
	if tree == nil || tree.Children["issuer"] == nil {
		t.Fatal("expected CRL tree with issuer node")
	}
}

func TestBuildTreeWithChain_zeroNextUpdate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	revocationList := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: "Unknown"},
		ThisUpdate: now,
	}
	tree := BuildTreeWithChain(revocationList, nil)
	if tree.Children["isCACRL"].Value != false {
		t.Fatalf("isCACRL = %v, want false when nextUpdate is zero", tree.Children["isCACRL"].Value)
	}
}
