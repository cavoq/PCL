package zcrypto_test

import (
	"testing"

	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/node"
)

func assertPathExists(t *testing.T, root *node.Node, path string) {
	t.Helper()

	if _, ok := root.Resolve(path); !ok {
		t.Fatalf("expected path %q to exist", path)
	}
}

func assertPathValue(t *testing.T, root *node.Node, path string, want any) {
	t.Helper()

	n, ok := root.Resolve(path)
	if !ok {
		t.Fatalf("path %q not found", path)
	}

	if n.Value != want {
		t.Fatalf(
			"path %q: expected %v (%T), got %v (%T)",
			path, want, want, n.Value, n.Value,
		)
	}
}

func TestZCryptoBuilder_PublicKeyRSA(t *testing.T) {
	loader := zcrypto.NewLoader()
	builder := zcrypto.NewZCryptoBuilder()

	data := loadTestCert(t, "leaf.pem")

	cert, err := loader.Load(data)
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}

	root := builder.Build(cert)

	if root.Name != "certificate" {
		t.Fatalf("expected root name 'certificate', got %q", root.Name)
	}

	assertPathExists(t, root,
		"certificate.subjectPublicKeyInfo.publicKey",
	)

	assertPathValue(t, root,
		"certificate.subjectPublicKeyInfo.publicKey.keySize",
		2048,
	)
}

func TestZCryptoBuilder_KeyUsageExpanded(t *testing.T) {
	loader := zcrypto.NewLoader()
	builder := zcrypto.NewZCryptoBuilder()

	data := loadTestCert(t, "leaf.pem")

	cert, err := loader.Load(data)
	if err != nil {
		t.Fatal(err)
	}

	root := builder.Build(cert)

	assertPathExists(t, root,
		"certificate.keyUsage",
	)

	assertPathExists(t, root,
		"certificate.keyUsage.digitalSignature",
	)
}

func TestZCryptoBuilder_SubjectFieldsPresent(t *testing.T) {
	loader := zcrypto.NewLoader()
	builder := zcrypto.NewZCryptoBuilder()

	cert, err := loader.Load(loadTestCert(t, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}

	root := builder.Build(cert)

	assertPathExists(t, root, "certificate.subject")
	assertPathExists(t, root, "certificate.subject.commonName")
}
