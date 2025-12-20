package zcrypto_test

import (
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/node"
)

func assertPathExists(t *testing.T, root *node.Node, path string) {
	t.Helper()
	if _, ok := root.Resolve(path); !ok {
		t.Errorf("expected path %q to exist", path)
	}
}

func assertPathNotExists(t *testing.T, root *node.Node, path string) {
	t.Helper()
	if _, ok := root.Resolve(path); ok {
		t.Errorf("expected path %q to not exist", path)
	}
}

func assertPathValue(t *testing.T, root *node.Node, path string, want any) {
	t.Helper()
	n, ok := root.Resolve(path)
	if !ok {
		t.Errorf("path %q not found", path)
		return
	}
	if n.Value != want {
		t.Errorf("path %q: expected %v (%T), got %v (%T)", path, want, want, n.Value, n.Value)
	}
}

func loadCert(t *testing.T, name string) *node.Node {
	t.Helper()
	loader := zcrypto.NewLoader()
	builder := zcrypto.NewZCryptoBuilder()

	cert, err := loader.Load(loadTestCert(t, name))
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}
	return builder.Build(cert)
}

func TestBuilder_RootName(t *testing.T) {
	root := loadCert(t, "leaf.pem")
	if root.Name != "certificate" {
		t.Errorf("expected root name 'certificate', got %q", root.Name)
	}
}

func TestBuilder_Version(t *testing.T) {
	root := loadCert(t, "leaf.pem")
	assertPathValue(t, root, "certificate.version", 3)
}

func TestBuilder_SerialNumber(t *testing.T) {
	root := loadCert(t, "leaf.pem")
	assertPathExists(t, root, "certificate.serialNumber")

	n, _ := root.Resolve("certificate.serialNumber")
	if n.Value == nil || n.Value == "" {
		t.Error("serialNumber should not be empty")
	}
}

func TestBuilder_SignatureAlgorithm(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.signatureAlgorithm")
	assertPathExists(t, root, "certificate.signatureAlgorithm.algorithm")
	assertPathExists(t, root, "certificate.signatureAlgorithm.oid")

	assertPathValue(t, root, "certificate.signatureAlgorithm.algorithm", "SHA256-RSA")
}

func TestBuilder_Issuer(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.issuer")
	assertPathValue(t, root, "certificate.issuer.commonName", "BSI Intermediate CA")
	assertPathValue(t, root, "certificate.issuer.countryName", "DE")
	assertPathValue(t, root, "certificate.issuer.organizationName", "ExampleOrg")
	assertPathValue(t, root, "certificate.issuer.organizationalUnitName", "Intermediate")
	assertPathValue(t, root, "certificate.issuer.localityName", "Berlin")
	assertPathValue(t, root, "certificate.issuer.stateOrProvinceName", "Berlin")
}

func TestBuilder_Subject(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.subject")
	assertPathValue(t, root, "certificate.subject.commonName", "leaf.example.test")
	assertPathValue(t, root, "certificate.subject.countryName", "DE")
	assertPathValue(t, root, "certificate.subject.organizationName", "ExampleOrg")
	assertPathValue(t, root, "certificate.subject.organizationalUnitName", "Leaf")
}

func TestBuilder_Validity(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.validity")
	assertPathExists(t, root, "certificate.validity.notBefore")
	assertPathExists(t, root, "certificate.validity.notAfter")

	notBefore, _ := root.Resolve("certificate.validity.notBefore")
	notAfter, _ := root.Resolve("certificate.validity.notAfter")

	if _, ok := notBefore.Value.(time.Time); !ok {
		t.Errorf("notBefore should be time.Time, got %T", notBefore.Value)
	}
	if _, ok := notAfter.Value.(time.Time); !ok {
		t.Errorf("notAfter should be time.Time, got %T", notAfter.Value)
	}
}

func TestBuilder_SubjectPublicKeyInfo_RSA(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.subjectPublicKeyInfo")
	assertPathExists(t, root, "certificate.subjectPublicKeyInfo.algorithm")
	assertPathValue(t, root, "certificate.subjectPublicKeyInfo.algorithm.algorithm", "RSA")

	assertPathExists(t, root, "certificate.subjectPublicKeyInfo.publicKey")
	assertPathValue(t, root, "certificate.subjectPublicKeyInfo.publicKey.keySize", 2048)
	assertPathValue(t, root, "certificate.subjectPublicKeyInfo.publicKey.exponent", 65537)
}

func TestBuilder_SubjectPublicKeyInfo_RSA4096(t *testing.T) {
	root := loadCert(t, "intermediate.pem")

	assertPathValue(t, root, "certificate.subjectPublicKeyInfo.publicKey.keySize", 4096)
}

func TestBuilder_KeyUsage_LeafCert(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.keyUsage")
	assertPathValue(t, root, "certificate.keyUsage.digitalSignature", true)
	assertPathValue(t, root, "certificate.keyUsage.keyEncipherment", true)

	assertPathNotExists(t, root, "certificate.keyUsage.keyCertSign")
	assertPathNotExists(t, root, "certificate.keyUsage.cRLSign")
}

func TestBuilder_KeyUsage_CACert(t *testing.T) {
	root := loadCert(t, "intermediate.pem")

	assertPathExists(t, root, "certificate.keyUsage")
	assertPathValue(t, root, "certificate.keyUsage.keyCertSign", true)
	assertPathValue(t, root, "certificate.keyUsage.cRLSign", true)
}

func TestBuilder_ExtKeyUsage(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.extKeyUsage")
	assertPathValue(t, root, "certificate.extKeyUsage.serverAuth", true)
}

func TestBuilder_BasicConstraints_LeafCert(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.basicConstraints")
	assertPathValue(t, root, "certificate.basicConstraints.cA", false)
}

func TestBuilder_BasicConstraints_CACert(t *testing.T) {
	root := loadCert(t, "intermediate.pem")

	assertPathExists(t, root, "certificate.basicConstraints")
	assertPathValue(t, root, "certificate.basicConstraints.cA", true)
	assertPathExists(t, root, "certificate.basicConstraints.pathLenConstraint")
}

func TestBuilder_SubjectAltName(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.subjectAltName")
	assertPathExists(t, root, "certificate.subjectAltName.dNSName")
	assertPathValue(t, root, "certificate.subjectAltName.dNSName.0", "leaf.example.test")
}

func TestBuilder_SubjectKeyIdentifier(t *testing.T) {
	root := loadCert(t, "leaf.pem")
	assertPathExists(t, root, "certificate.subjectKeyIdentifier")

	n, _ := root.Resolve("certificate.subjectKeyIdentifier")
	if n.Value == nil {
		t.Error("subjectKeyIdentifier should not be nil")
	}
}

func TestBuilder_AuthorityKeyIdentifier(t *testing.T) {
	root := loadCert(t, "leaf.pem")
	assertPathExists(t, root, "certificate.authorityKeyIdentifier")

	n, _ := root.Resolve("certificate.authorityKeyIdentifier")
	if n.Value == nil {
		t.Error("authorityKeyIdentifier should not be nil")
	}
}

func TestBuilder_Extensions(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.extensions")

	extensions, _ := root.Resolve("certificate.extensions")
	if len(extensions.Children) == 0 {
		t.Error("expected at least one extension")
	}
}

func TestBuilder_SignatureValue(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	assertPathExists(t, root, "certificate.signatureValue")

	n, _ := root.Resolve("certificate.signatureValue")
	sig, ok := n.Value.([]byte)
	if !ok {
		t.Errorf("signatureValue should be []byte, got %T", n.Value)
	}
	if len(sig) == 0 {
		t.Error("signatureValue should not be empty")
	}
}

func TestBuilder_BuildTree(t *testing.T) {
	loader := zcrypto.NewLoader()
	cert, err := loader.Load(loadTestCert(t, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}

	root := zcrypto.BuildTree(cert)
	if root.Name != "certificate" {
		t.Errorf("expected root name 'certificate', got %q", root.Name)
	}
}

func TestBuilder_NoSubjectAltName(t *testing.T) {
	root := loadCert(t, "intermediate.pem")
	assertPathNotExists(t, root, "certificate.subjectAltName")
}

func TestBuilder_ExtensionDetails(t *testing.T) {
	root := loadCert(t, "leaf.pem")

	extensions, ok := root.Resolve("certificate.extensions")
	if !ok {
		t.Fatal("extensions not found")
	}

	for _, ext := range extensions.Children {
		if _, ok := ext.Children["oid"]; !ok {
			t.Errorf("extension %s missing oid", ext.Name)
		}
		if _, ok := ext.Children["critical"]; !ok {
			t.Errorf("extension %s missing critical", ext.Name)
		}
		if _, ok := ext.Children["value"]; !ok {
			t.Errorf("extension %s missing value", ext.Name)
		}
	}
}
