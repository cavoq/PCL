package zcrypto

import (
	"bytes"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/ct"
)

func TestBuildSCT(t *testing.T) {
	logID := ct.SHA256Hash{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	timestamp := uint64(1_704_067_200_123)
	signature := []byte{0xde, 0xad, 0xbe, 0xef}

	cert := &x509.Certificate{
		SignedCertificateTimestampList: []*ct.SignedCertificateTimestamp{
			{
				SCTVersion: ct.V1,
				LogID:      logID,
				Timestamp:  timestamp,
				Extensions: ct.CTExtensions{0x01, 0x02},
				Signature: ct.DigitallySigned{
					HashAlgorithm:      ct.SHA256,
					SignatureAlgorithm: ct.ECDSA,
					Signature:          signature,
				},
			},
		},
	}

	tree := BuildTree(cert)
	sctNode, ok := tree.Resolve("certificate.signedCertificateTimestamps.0")
	if !ok {
		t.Fatal("expected first SCT node")
	}

	assertSCTValue(t, sctNode, "present", true)
	assertSCTValue(t, sctNode, "version", 0)
	assertSCTValue(t, sctNode, "versionString", "V1")
	assertSCTValue(t, sctNode, "logIDHex", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	assertSCTValue(t, sctNode, "timestamp", timestamp)
	assertSCTValue(t, sctNode, "timestampTime", time.Unix(0, int64(timestamp)*int64(time.Millisecond)))
	assertSCTValue(t, sctNode, "extensionsLen", 2)
	assertSCTValue(t, sctNode, "signatureAlgorithmString", "SHA256-ECDSA")

	logIDNode, ok := sctNode.Resolve("logID")
	if !ok {
		t.Fatal("expected logID node")
	}
	gotLogID, ok := logIDNode.Value.([]byte)
	if !ok {
		t.Fatalf("expected logID to be []byte, got %T", logIDNode.Value)
	}
	if !bytes.Equal(gotLogID, logID[:]) {
		t.Fatalf("logID mismatch: got %x, want %x", gotLogID, logID[:])
	}

	assertSCTValue(t, sctNode, "signature.hashAlgorithm", "SHA256")
	assertSCTValue(t, sctNode, "signature.hashAlgorithmValue", int(ct.SHA256))
	assertSCTValue(t, sctNode, "signature.signatureAlgorithm", "ECDSA")
	assertSCTValue(t, sctNode, "signature.signatureAlgorithmValue", int(ct.ECDSA))
	assertSCTValue(t, sctNode, "signature.signatureValueHex", "deadbeef")

	signatureNode, ok := sctNode.Resolve("signature.signatureValue")
	if !ok {
		t.Fatal("expected signatureValue node")
	}
	gotSignature, ok := signatureNode.Value.([]byte)
	if !ok {
		t.Fatalf("expected signatureValue to be []byte, got %T", signatureNode.Value)
	}
	if !bytes.Equal(gotSignature, signature) {
		t.Fatalf("signatureValue mismatch: got %x, want %x", gotSignature, signature)
	}
}

func assertSCTValue(t *testing.T, root *node.Node, path string, want any) {
	t.Helper()
	gotNode, ok := root.Resolve(path)
	if !ok {
		t.Fatalf("expected path %q to exist", path)
	}
	if gotNode.Value != want {
		t.Fatalf("%q: got %v (%T), want %v (%T)", path, gotNode.Value, gotNode.Value, want, want)
	}
}
