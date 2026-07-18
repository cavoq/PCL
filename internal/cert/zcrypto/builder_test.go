package zcrypto

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/cavoq/PCL/internal/node"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
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

func TestBuilder_ProjectsMalformedDecodedExtensions(t *testing.T) {
	cert := &x509.Certificate{Extensions: []pkix.Extension{
		{Id: zasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x00}},
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 31}, Value: []byte{0x30, 0x00}},
		{Id: zasn1.ObjectIdentifier{2, 5, 29, 32}, Value: []byte{0x30, 0x00}},
	}}

	tree := BuildTree(cert)
	for _, path := range []string{
		"certificate.extensions.1.3.6.1.5.5.7.1.1.malformed",
		"certificate.extensions.2.5.29.31.malformed",
		"certificate.extensions.2.5.29.32.malformed",
	} {
		assertPathValue(t, tree, path, true)
	}
}

func loadCert(t *testing.T, name string) *node.Node {
	t.Helper()
	loader := NewLoader()
	builder := NewZCryptoBuilder()

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
	assertPathExists(t, root, "certificate.signatureAlgorithm.rawDER")
	assertPathExists(t, root, "certificate.tbsSignatureAlgorithm.rawDER")

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

func TestBuilder_SubjectAndIssuerUseRawNameProjection(t *testing.T) {
	cert, err := NewLoader().Load(loadTestCert(t, "leaf.pem"))
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	tree := BuildTree(cert)

	for _, test := range []struct {
		path string
		raw  []byte
	}{
		{path: "certificate.subject", raw: cert.RawSubject},
		{path: "certificate.issuer", raw: cert.RawIssuer},
	} {
		name, ok := tree.Resolve(test.path)
		if !ok {
			t.Fatalf("missing %s", test.path)
		}
		raw := name.Children["raw"]
		if raw == nil || !bytes.Equal(raw.Value.([]byte), test.raw) {
			t.Errorf("%s raw DER was not preserved", test.path)
		}
		if len(node.CollectionElements(name.Children["rdns"])) == 0 {
			t.Errorf("%s has no projected RDNs", test.path)
		}
		commonNames := name.Children["commonName"]
		if commonNames == nil || len(node.CollectionElements(commonNames)) == 0 {
			t.Errorf("%s has no commonName occurrences", test.path)
			continue
		}
		attribute := node.CollectionElements(commonNames)[0]
		if attribute.Children["value"] == nil || attribute.Children["encoding"] == nil ||
			attribute.Children["raw"] == nil {
			t.Errorf("%s commonName lacks value/encoding/raw metadata", test.path)
		}
	}
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
	assertPathValue(t, root, "certificate.validity.notBefore.encoding", 23)
	assertPathValue(t, root, "certificate.validity.notBefore.isUTC", true)
	assertPathValue(t, root, "certificate.validity.notBefore.hasSeconds", true)
	assertPathValue(t, root, "certificate.validity.notBefore.hasZulu", true)
	assertPathValue(t, root, "certificate.validity.notAfter.encoding", 23)
	assertPathValue(t, root, "certificate.validity.notAfter.isUTC", true)
	assertPathValue(t, root, "certificate.validity.notAfter.hasSeconds", true)
	assertPathValue(t, root, "certificate.validity.notAfter.hasZulu", true)
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

	assertPathValue(t, root, "certificate.keyUsage.keyCertSign", false)
	assertPathValue(t, root, "certificate.keyUsage.cRLSign", false)
}

func TestBuilder_KeyUsage_CACert(t *testing.T) {
	root := loadCert(t, "intermediate.pem")

	assertPathExists(t, root, "certificate.keyUsage")
	assertPathValue(t, root, "certificate.keyUsage.keyCertSign", true)
	assertPathValue(t, root, "certificate.keyUsage.cRLSign", true)
}

func TestBuilder_KeyUsagePresenceComesFromExtension(t *testing.T) {
	withoutExtension := BuildTree(&x509.Certificate{})
	assertPathNotExists(t, withoutExtension, "certificate.keyUsage")

	withExtension := BuildTree(&x509.Certificate{
		Extensions: []pkix.Extension{{Id: zasn1.ObjectIdentifier{2, 5, 29, 15}}},
	})
	assertPathExists(t, withExtension, "certificate.keyUsage")
	assertPathValue(t, withExtension, "certificate.keyUsage.digitalSignature", false)
	assertPathValue(t, withExtension, "certificate.keyUsage.keyCertSign", false)
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
	loader := NewLoader()
	cert, err := loader.Load(loadTestCert(t, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}

	root := BuildTree(cert)
	if root.Name != "certificate" {
		t.Errorf("expected root name 'certificate', got %q", root.Name)
	}
}

func TestBuilder_NoSubjectAltName(t *testing.T) {
	root := loadCert(t, "intermediate.pem")
	assertPathNotExists(t, root, "certificate.subjectAltName")
}

func TestBuilder_SubjectAltNameUsesExtensionAndAllGeneralNameForms(t *testing.T) {
	registeredID := zasn1.ObjectIdentifier{1, 2}
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{{
			Id:    zasn1.ObjectIdentifier{2, 5, 29, 17},
			Value: []byte{0x30, 0x03, 0x88, 0x01, 0x2a},
		}},
		RegisteredIDs: []zasn1.ObjectIdentifier{registeredID},
	}
	root := BuildTree(cert)
	assertPathValue(t, root, "certificate.subjectAltName", 1)
	assertPathValue(t, root, "certificate.subjectAltName.registeredID.0", registeredID.String())

	x400Only := BuildTree(&x509.Certificate{Extensions: []pkix.Extension{{
		Id:    zasn1.ObjectIdentifier{2, 5, 29, 17},
		Value: []byte{0x30, 0x09, 0xa3, 0x07, 0x30, 0x05, 0x83, 0x03, 'O', 'r', 'g'},
	}}})
	assertPathValue(t, x400Only, "certificate.subjectAltName", 1)
	assertPathExists(t, x400Only, "certificate.subjectAltName.x400Address.0")

	empty := BuildTree(&x509.Certificate{Extensions: []pkix.Extension{{
		Id:    zasn1.ObjectIdentifier{2, 5, 29, 17},
		Value: []byte{0x30, 0x00},
	}}})
	assertPathValue(t, empty, "certificate.subjectAltName.malformed", true)
}

func TestBuilder_SubjectAltNameDirectoryNameUsesRawProjection(t *testing.T) {
	// GeneralNames { directoryName { commonName = UTF8String("directory") } }
	value := []byte{
		0x30, 0x18, 0xa4, 0x16, 0x30, 0x14, 0x31, 0x12,
		0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
		0x09, 'd', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y',
	}
	root := BuildTree(&x509.Certificate{Extensions: []pkix.Extension{{
		Id:    zasn1.ObjectIdentifier{2, 5, 29, 17},
		Value: value,
	}}})

	assertPathValue(t, root, "certificate.subjectAltName", 1)
	assertPathValue(t, root, "certificate.subjectAltName.directoryName.0.commonName.0.value", "directory")
	assertPathValue(t, root, "certificate.subjectAltName.directoryName.0.commonName.0.encoding", 12)
	assertPathExists(t, root, "certificate.subjectAltName.directoryName.0.rdns.0.attributes.0.raw")
}

func TestBuilder_MalformedRawGeneralNamesDoNotLeaveTypedFallback(t *testing.T) {
	value := []byte{0x30, 0x04, 0xa4, 0x02, 0x30, 0x00}
	root := BuildTree(&x509.Certificate{
		DirectoryNames: []pkix.Name{{CommonName: "lossy fallback"}},
		Extensions: []pkix.Extension{{
			Id:    zasn1.ObjectIdentifier{2, 5, 29, 17},
			Value: value,
		}},
	})

	assertPathValue(t, root, "certificate.subjectAltName.malformed", true)
	assertPathNotExists(t, root, "certificate.subjectAltName.directoryName")
	raw, ok := root.Resolve("certificate.subjectAltName.raw")
	if !ok || !bytes.Equal(raw.Value.([]byte), value) {
		t.Fatal("malformed GeneralNames raw DER was not preserved")
	}
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

func TestBuilder_AIAStructure(t *testing.T) {
	data, err := os.ReadFile("../../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	loader := NewLoader()
	cert, err := loader.Load(data)
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}

	node := BuildTree(cert)

	exts := node.Children["extensions"]
	if exts == nil {
		t.Fatal("no extensions")
	}

	// Check AIA friendly name exists
	aia, ok := exts.Children["authorityInfoAccess"]
	if !ok {
		t.Fatal("authorityInfoAccess friendly name not found")
	}

	// Check AIA OID exists
	aiaOID, ok := exts.Children["1.3.6.1.5.5.7.1.1"]
	if !ok {
		t.Fatal("AIA OID not found")
	}

	// Should point to same node
	if aia != aiaOID {
		t.Error("friendly name and OID should point to same node")
	}

	// Check parsed accessDescriptions exist
	ads, ok := aia.Children["accessDescriptions"]
	if !ok {
		t.Fatal("accessDescriptions not found")
	}

	// Check count
	count, ok := aia.Children["count"]
	if !ok {
		t.Fatal("count not found")
	}
	t.Logf("AIA count: %v", count.Value)

	// Check first accessDescription
	ad0, ok := ads.Children["0"]
	if !ok {
		t.Fatal("first accessDescription not found")
	}

	method, ok := ad0.Children["accessMethod"]
	if !ok {
		t.Fatal("accessMethod not found")
	}
	t.Logf("First accessMethod: %v", method.Value)

	loc, ok := ad0.Children["accessLocation"]
	if !ok {
		t.Fatal("accessLocation not found")
	}
	locType, ok := loc.Children["type"]
	if !ok {
		t.Fatal("accessLocation type not found")
	}
	t.Logf("accessLocation type: %v", locType.Value)
	locTag, ok := loc.Children["tag"]
	if !ok {
		t.Fatal("accessLocation tag not found")
	}
	locTagInt, ok2 := locTag.Value.(int)
	if !ok2 || locTagInt != 6 {
		t.Errorf("expected URI tag 6, got %v", locTag.Value)
	}

	// Check containsOCSP and containsCaIssuers
	hasOCSP, ok := aia.Children["containsOCSP"]
	if ok {
		t.Logf("containsOCSP: %v", hasOCSP.Value)
	}
	hasCaIssuers, ok := aia.Children["containsCaIssuers"]
	if ok {
		t.Logf("containsCaIssuers: %v", hasCaIssuers.Value)
	}
}

func TestBuilder_CRLDPStructure(t *testing.T) {
	data, err := os.ReadFile("../../../tests/certs/leaf.pem")
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	loader := NewLoader()
	cert, err := loader.Load(data)
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}

	node := BuildTree(cert)

	exts := node.Children["extensions"]
	if exts == nil {
		t.Fatal("no extensions")
	}

	// Check CRL DP friendly name exists
	crlDP, ok := exts.Children["cRLDistributionPoints"]
	if !ok {
		t.Fatal("cRLDistributionPoints friendly name not found")
	}

	// Check CRL DP OID exists
	crlDPOID, ok := exts.Children["2.5.29.31"]
	if !ok {
		t.Fatal("CRL DP OID not found")
	}

	// Should point to same node
	if crlDP != crlDPOID {
		t.Error("friendly name and OID should point to same node")
	}

	// Check parsed distributionPoints exist
	dps, ok := crlDP.Children["distributionPoints"]
	if !ok {
		t.Fatal("distributionPoints not found")
	}

	// Check first distributionPoint
	dp0, ok := dps.Children["0"]
	if !ok {
		t.Fatal("first distributionPoint not found")
	}

	// Check hasReasons and hasCRLIssuer
	hasReasons, ok := dp0.Children["hasReasons"]
	if ok {
		t.Logf("hasReasons: %v", hasReasons.Value)
		if hasReasonsVal, ok2 := hasReasons.Value.(bool); ok2 && hasReasonsVal {
			t.Error("should not have reasons field for test cert")
		}
	}
	hasCRLIssuer, ok := dp0.Children["hasCRLIssuer"]
	if ok {
		t.Logf("hasCRLIssuer: %v", hasCRLIssuer.Value)
		if hasCRLIssuerVal, ok2 := hasCRLIssuer.Value.(bool); ok2 && hasCRLIssuerVal {
			t.Error("should not have cRLIssuer field for test cert")
		}
	}

	// Check distributionPoint fullName
	dp, ok := dp0.Children["distributionPoint"]
	if !ok {
		t.Fatal("distributionPoint not found")
	}
	fullName, ok := dp.Children["fullName"]
	if !ok {
		t.Fatal("fullName not found")
	}
	gn0, ok := fullName.Children["generalNames"].Children["0"]
	if !ok {
		t.Fatal("first generalName not found")
	}
	gnType, ok := gn0.Children["type"]
	if !ok {
		t.Fatal("generalName type not found")
	}
	t.Logf("GeneralName type: %v", gnType.Value)
	gnTypeStr, ok2 := gnType.Value.(string)
	if !ok2 || gnTypeStr != "uniformResourceIdentifier" {
		t.Errorf("expected URI type, got %v", gnType.Value)
	}
	scheme, ok := gn0.Children["scheme"]
	if ok {
		t.Logf("Scheme: %v", scheme.Value)
	}
}

func TestBuilder_NameConstraints(t *testing.T) {
	root := loadCert(t, "nc_ca.pem")

	// Check nameConstraints node exists
	assertPathExists(t, root, "certificate.nameConstraints")

	// Check critical flag
	assertPathValue(t, root, "certificate.nameConstraints.critical", true)

	// Check permittedSubtrees exists
	assertPathExists(t, root, "certificate.nameConstraints.permittedSubtrees")

	// Check permittedSubtrees.dNSName exists
	assertPathExists(t, root, "certificate.nameConstraints.permittedSubtrees.dNSName")

	// Check first DNS constraint value
	dns0, ok := root.Resolve("certificate.nameConstraints.permittedSubtrees.dNSName.0")
	if !ok {
		t.Fatal("DNS constraint 0 not found")
	}
	if dns0.Children["value"] == nil {
		t.Error("DNS constraint should have value")
	}
	t.Logf("DNS constraint 0 value: %v", dns0.Children["value"].Value)

	// Check permittedSubtrees.iPAddress exists
	assertPathExists(t, root, "certificate.nameConstraints.permittedSubtrees.iPAddress")

	// Check min/max are NOT present (BR requirement)
	assertPathNotExists(t, root, "certificate.nameConstraints.permittedSubtrees.dNSName.0.min")
	assertPathNotExists(t, root, "certificate.nameConstraints.permittedSubtrees.dNSName.0.max")
}
