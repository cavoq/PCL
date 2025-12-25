package zcrypto

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/zmap/zcrypto/x509"
)

func loadTestCRL(t *testing.T, name string) *x509.RevocationList {
	t.Helper()

	path := filepath.Join("..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test CRL %s: %v", name, err)
	}

	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		t.Fatalf("failed to parse test CRL %s: %v", name, err)
	}

	return crl
}

func TestBuildTree_Basic(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	if tree == nil {
		t.Fatal("expected tree, got nil")
	}
	if tree.Name != "crl" {
		t.Errorf("expected root name 'crl', got %q", tree.Name)
	}
}

func TestBuildTree_Issuer(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	issuer, ok := tree.Resolve("issuer")
	if !ok || issuer == nil {
		t.Fatal("expected issuer node")
	}

	cn, ok := tree.Resolve("issuer.commonName")
	if !ok || cn == nil {
		t.Fatal("expected issuer.commonName node")
	}
	if cn.Value != "Test CA" {
		t.Errorf("expected CN 'Test CA', got %v", cn.Value)
	}
}

func TestBuildTree_ThisUpdate(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	thisUpdate, ok := tree.Resolve("thisUpdate")
	if !ok || thisUpdate == nil {
		t.Fatal("expected thisUpdate node")
	}
	if thisUpdate.Value == nil {
		t.Error("expected thisUpdate value")
	}
}

func TestBuildTree_NextUpdate(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	nextUpdate, ok := tree.Resolve("nextUpdate")
	if !ok || nextUpdate == nil {
		t.Fatal("expected nextUpdate node")
	}
}

func TestBuildTree_SignatureAlgorithm(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	sigAlgo, ok := tree.Resolve("signatureAlgorithm")
	if !ok || sigAlgo == nil {
		t.Fatal("expected signatureAlgorithm node")
	}

	algo, ok := tree.Resolve("signatureAlgorithm.algorithm")
	if !ok || algo == nil {
		t.Fatal("expected signatureAlgorithm.algorithm node")
	}
	if algo.Value == nil || algo.Value == "" {
		t.Error("expected algorithm value")
	}
}

func TestBuildTree_RevokedCertificates(t *testing.T) {
	crl := loadTestCRL(t, "test_with_revoked.crl")
	tree := BuildTree(crl)

	revoked, ok := tree.Resolve("revokedCertificates")
	if !ok || revoked == nil {
		t.Fatal("expected revokedCertificates node")
	}
	if len(revoked.Children) == 0 {
		t.Error("expected at least one revoked certificate")
	}

	first, ok := tree.Resolve("revokedCertificates.0")
	if !ok || first == nil {
		t.Fatal("expected first revoked certificate")
	}

	serial, ok := tree.Resolve("revokedCertificates.0.serialNumber")
	if !ok || serial == nil {
		t.Fatal("expected serialNumber in revoked certificate")
	}

	revDate, ok := tree.Resolve("revokedCertificates.0.revocationDate")
	if !ok || revDate == nil {
		t.Fatal("expected revocationDate in revoked certificate")
	}
}

func TestBuildTree_SignatureValue(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	sig, ok := tree.Resolve("signatureValue")
	if !ok || sig == nil {
		t.Fatal("expected signatureValue node")
	}
	if sig.Value == nil {
		t.Error("expected signature value")
	}
}

func TestNewCRLBuilder(t *testing.T) {
	builder := NewCRLBuilder()
	if builder == nil {
		t.Fatal("expected builder, got nil")
	}

	crl := loadTestCRL(t, "test.crl")
	tree := builder.Build(crl)
	if tree == nil {
		t.Fatal("expected tree from builder")
	}
}

func TestBuildTree_EmptyCRL(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)

	revoked, ok := tree.Resolve("revokedCertificates")
	if ok && revoked != nil {
		t.Error("empty CRL should not have revokedCertificates node")
	}
}
