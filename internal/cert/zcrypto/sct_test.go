package zcrypto

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/zmap/zcrypto/x509"
)

func TestBuildSCT(t *testing.T) {
	// Read Let's Encrypt certificate
	data, err := os.ReadFile("../../../tests/certs/letsencrypt.pem")
	if err != nil {
		t.Skipf("Error reading cert: %v", err)
		return
	}

	// Parse PEM
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Error parsing cert: %v", err)
	}

	t.Logf("SCT count in cert: %d", len(cert.SignedCertificateTimestampList))

	// Build node tree
	tree := BuildTree(cert)

	// Get SCT node
	sctNode := tree.Children["signedCertificateTimestamps"]
	if sctNode == nil {
		if len(cert.SignedCertificateTimestampList) == 0 {
			t.Log("No SCTs in certificate")
			return
		}
		t.Fatal("SCT node missing when SCTs exist")
		return
	}

	// Print SCT structure
	t.Log("\nSCT Node Tree:")
	for key, child := range sctNode.Children {
		t.Logf("\n=== SCT %s ===", key)
		for field, val := range child.Children {
			if val.Value != nil {
				t.Logf("  %s: %v", field, val.Value)
			}
		}
	}

	// Verify first SCT has required fields
	if len(sctNode.Children) > 0 {
		firstSCT := sctNode.Children["0"]
		if firstSCT == nil {
			t.Fatal("First SCT missing")
		}

		// Check logID
		if firstSCT.Children["logID"] == nil {
			t.Error("logID field missing")
		}
		if firstSCT.Children["logIDHex"] == nil {
			t.Error("logIDHex field missing")
		}

		// Check timestamp
		if firstSCT.Children["timestamp"] == nil {
			t.Error("timestamp field missing")
		}
		if firstSCT.Children["timestampTime"] == nil {
			t.Error("timestampTime field missing")
		}

		// Check version
		if firstSCT.Children["version"] == nil {
			t.Error("version field missing")
		}

		// Check signature
		if firstSCT.Children["signature"] == nil {
			t.Error("signature field missing")
		}

		t.Logf("\nAll required fields present for SCT 0")
	}
}
