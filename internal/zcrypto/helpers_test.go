package zcrypto

import (
	"testing"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestToStdCert_Nil(t *testing.T) {
	cert, err := ToStdCert(nil)
	if err != nil {
		t.Errorf("unexpected error for nil cert: %v", err)
	}
	if cert != nil {
		t.Error("expected nil result for nil input")
	}
}

func TestBuildPkixName_Empty(t *testing.T) {
	name := pkix.Name{}
	node := BuildPkixName("subject", name)

	if node == nil {
		t.Fatal("expected non-nil node")
	}
	if node.Name != "subject" {
		t.Errorf("expected name 'subject', got %q", node.Name)
	}
	if len(node.Children) != 0 {
		t.Errorf("expected no children for empty name, got %d", len(node.Children))
	}
}

func TestBuildPkixName_AllFields(t *testing.T) {
	name := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Test Org"},
		OrganizationalUnit: []string{"Test Unit"},
		CommonName:         "Test CN",
		Locality:           []string{"Test City"},
		Province:           []string{"Test State"},
		StreetAddress:      []string{"123 Test St"},
		PostalCode:         []string{"12345"},
		SerialNumber:       "SN123",
	}

	node := BuildPkixName("issuer", name)

	if node == nil {
		t.Fatal("expected non-nil node")
	}
	if node.Name != "issuer" {
		t.Errorf("expected name 'issuer', got %q", node.Name)
	}

	tests := []struct {
		key      string
		expected string
	}{
		{"countryName", "US"},
		{"organizationName", "Test Org"},
		{"organizationalUnitName", "Test Unit"},
		{"commonName", "Test CN"},
		{"localityName", "Test City"},
		{"stateOrProvinceName", "Test State"},
		{"streetAddress", "123 Test St"},
		{"postalCode", "12345"},
		{"serialNumber", "SN123"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			child, ok := node.Children[tt.key]
			if !ok {
				t.Fatalf("expected child %q", tt.key)
			}
			if child.Value != tt.expected {
				t.Errorf("expected value %q, got %v", tt.expected, child.Value)
			}
		})
	}
}

func TestBuildPkixName_PartialFields(t *testing.T) {
	name := pkix.Name{
		CommonName:   "Only CN",
		Organization: []string{"Only Org"},
	}

	node := BuildPkixName("subject", name)

	if len(node.Children) != 2 {
		t.Errorf("expected 2 children, got %d", len(node.Children))
	}

	if _, ok := node.Children["commonName"]; !ok {
		t.Error("expected commonName child")
	}
	if _, ok := node.Children["organizationName"]; !ok {
		t.Error("expected organizationName child")
	}
	if _, ok := node.Children["countryName"]; ok {
		t.Error("should not have countryName child")
	}
}

func TestBuildExtensions_Empty(t *testing.T) {
	node := BuildExtensions(nil)

	if node == nil {
		t.Fatal("expected non-nil node")
	}
	if node.Name != "extensions" {
		t.Errorf("expected name 'extensions', got %q", node.Name)
	}
	if len(node.Children) != 0 {
		t.Errorf("expected no children for empty extensions, got %d", len(node.Children))
	}
}

func TestBuildExtensions_WithExtensions(t *testing.T) {
	extensions := []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // keyUsage
			Critical: true,
			Value:    []byte{0x03, 0x02, 0x05, 0xa0},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // extKeyUsage
			Critical: false,
			Value:    []byte{0x30, 0x00},
		},
	}

	node := BuildExtensions(extensions)

	if len(node.Children) != 2 {
		t.Fatalf("expected 2 extension children, got %d", len(node.Children))
	}

	// Check keyUsage extension
	kuOID := "2.5.29.15"
	kuExt, ok := node.Children[kuOID]
	if !ok {
		t.Fatalf("expected extension %s", kuOID)
	}

	if kuExt.Children["oid"].Value != kuOID {
		t.Errorf("expected oid %q, got %v", kuOID, kuExt.Children["oid"].Value)
	}
	if kuExt.Children["critical"].Value != true {
		t.Errorf("expected critical=true, got %v", kuExt.Children["critical"].Value)
	}

	// Check extKeyUsage extension
	ekuOID := "2.5.29.37"
	ekuExt, ok := node.Children[ekuOID]
	if !ok {
		t.Fatalf("expected extension %s", ekuOID)
	}

	if ekuExt.Children["critical"].Value != false {
		t.Errorf("expected critical=false, got %v", ekuExt.Children["critical"].Value)
	}
}

func TestBuildExtensions_ExtensionStructure(t *testing.T) {
	extensions := []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
			Critical: true,
			Value:    []byte{0x01, 0x02},
		},
	}

	node := BuildExtensions(extensions)
	extNode := node.Children["1.2.3.4"]

	// Check that each extension has the required child nodes
	requiredChildren := []string{"oid", "critical", "value"}
	for _, child := range requiredChildren {
		if _, ok := extNode.Children[child]; !ok {
			t.Errorf("extension should have %q child", child)
		}
	}
}
