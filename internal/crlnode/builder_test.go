package crlnode

import (
	"bytes"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/testfiles"
	"github.com/cavoq/PCL/internal/x509ext"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func loadTestCRL(t *testing.T, name string) *x509.RevocationList {
	t.Helper()

	path := testfiles.CRLTestdata(name)
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

func TestBuildTree_IssuerUsesRawNameProjection(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	tree := BuildTree(crl)
	issuer, ok := tree.Resolve("issuer")
	if !ok {
		t.Fatal("missing issuer")
	}
	if raw := issuer.Children["raw"]; raw == nil || !bytes.Equal(raw.Value.([]byte), crl.RawIssuer) {
		t.Fatal("CRL issuer raw DER was not preserved")
	}
	if len(node.CollectionElements(issuer.Children["rdns"])) == 0 {
		t.Fatal("CRL issuer has no projected RDNs")
	}
	commonNames := node.CollectionElements(issuer.Children["commonName"])
	if len(commonNames) == 0 || commonNames[0].Children["encoding"] == nil {
		t.Fatal("CRL issuer commonName lacks occurrence encoding metadata")
	}
}

func TestBuildTree_MalformedRawIssuerDoesNotUseParsedFallback(t *testing.T) {
	tree := BuildTree(&x509.RevocationList{
		RawIssuer: []byte{0x30, 0x01, 0x00},
		Issuer:    pkix.Name{CommonName: "lossy fallback"},
	})
	issuer, ok := tree.Resolve("issuer")
	if !ok {
		t.Fatal("missing issuer")
	}
	if malformed := issuer.Children["malformed"]; malformed == nil || malformed.Value != true {
		t.Fatal("malformed raw CRL issuer was not marked")
	}
	if issuer.Children["attributes"] != nil || issuer.Children["commonName"] != nil {
		t.Fatal("malformed raw CRL issuer exposed lossy fallback attributes")
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

func TestBuildTree_MissingNextUpdate(t *testing.T) {
	tree := BuildTree(&x509.RevocationList{})
	if _, ok := tree.Resolve("nextUpdate"); ok {
		t.Fatal("zero nextUpdate must remain absent in the node representation")
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
	if _, ok := tree.Resolve("signatureAlgorithm.rawDER"); !ok {
		t.Error("expected outer AlgorithmIdentifier raw DER")
	}
	if _, ok := tree.Resolve("tbsSignatureAlgorithm.rawDER"); !ok {
		t.Error("expected TBS AlgorithmIdentifier raw DER")
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

func TestBuildTree_RevokedEntryExtensionsUseSharedProjection(t *testing.T) {
	reason := 1
	rawReason := []byte{0x0a, 0x01, 0x01}
	tree := BuildTree(&x509.RevocationList{RevokedCertificates: []x509.RevokedCertificate{{
		SerialNumber: big.NewInt(7),
		ReasonCode:   &reason,
		Extensions: []pkix.Extension{{
			Id:       zasn1.ObjectIdentifier{2, 5, 29, 21},
			Critical: true,
			Value:    rawReason,
		}},
	}}})

	critical, ok := tree.Resolve("revokedCertificates.0.extensions.2.5.29.21.critical")
	if !ok || critical.Value != true {
		t.Fatalf("reason criticality = %#v, want true", critical)
	}
	value, ok := tree.Resolve("revokedCertificates.0.extensions.2.5.29.21.value")
	if !ok || value.Value != reason {
		t.Fatalf("semantic reason value = %#v, want %d", value, reason)
	}
	raw, ok := tree.Resolve("revokedCertificates.0.extensions.2.5.29.21.rawValue")
	if !ok || string(raw.Value.([]byte)) != string(rawReason) {
		t.Fatalf("raw reason value = %#v, want %x", raw, rawReason)
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

func TestBuildTree_AuthorityKeyIdentifierExtension(t *testing.T) {
	crl := &x509.RevocationList{
		Extensions: []pkix.Extension{{
			Id:       zasn1.ObjectIdentifier{2, 5, 29, 35},
			Critical: false,
		}},
	}

	tree := BuildTree(crl)
	byOID, ok := tree.Resolve("extensions.2.5.29.35.critical")
	if !ok || byOID.Value != false {
		t.Fatalf("expected non-critical CRL authorityKeyIdentifier by OID, got %#v", byOID)
	}
	byName, ok := tree.Resolve("extensions.authorityKeyIdentifier.critical")
	if !ok || byName != byOID {
		t.Fatal("expected authorityKeyIdentifier friendly path to alias OID 2.5.29.35")
	}
}

func TestAuthorityKeyIdentifierParsesExtensionValue(t *testing.T) {
	crl := loadTestCRL(t, "test.crl")
	keyIdentifier := x509ext.AuthorityKeyIdentifier(crl)
	if len(keyIdentifier) == 0 {
		t.Fatal("expected semantic authority key identifier")
	}
	if len(crl.AuthorityKeyId) <= len(keyIdentifier) {
		t.Fatalf("fixture should expose zcrypto's wrapped AKI value: raw=%d semantic=%d", len(crl.AuthorityKeyId), len(keyIdentifier))
	}

	tree := BuildTree(crl)
	aki, ok := tree.Resolve("authorityKeyIdentifier")
	if !ok {
		t.Fatal("authorityKeyIdentifier node missing")
	}
	got := aki.Value.([]byte)
	if string(got) != string(keyIdentifier) {
		t.Fatalf("builder AKI = %x, want %x", got, keyIdentifier)
	}
}

func TestBuildTreeProjectsStrictCRLExtensionsAndMalformedMarkers(t *testing.T) {
	list := &x509.RevocationList{Extensions: []pkix.Extension{
		{Id: oidObject(oid.CRLNumber), Value: []byte{0x02, 0x01, 0x05}},
		{Id: oidObject(oid.IssuingDistributionPoint), Critical: true, Value: []byte{0x30, 0x03, 0x84, 0x01, 0xff}},
	}}
	tree := BuildTree(list)
	if value, ok := tree.Resolve("extensions.cRLNumber.decimal"); !ok || value.Value != "5" {
		t.Fatalf("cRLNumber projection = %#v", value)
	}
	if indirect, ok := tree.Resolve("issuingDistributionPoint.indirectCRL"); !ok || indirect.Value != true {
		t.Fatalf("IDP projection = %#v", indirect)
	}

	malformed := BuildTree(&x509.RevocationList{Extensions: []pkix.Extension{{
		Id:       oidObject(oid.IssuingDistributionPoint),
		Critical: true,
		Value:    []byte{0x30, 0x03, 0x84, 0x01, 0x00},
	}}})
	marker, ok := malformed.Resolve("extensions.issuingDistributionPoint.malformed")
	if !ok || marker.Value != true {
		t.Fatalf("malformed marker = %#v", marker)
	}
}

func TestBuildTreeProjectsCanonicalReasonFlagsSchema(t *testing.T) {
	list := &x509.RevocationList{Extensions: []pkix.Extension{{
		Id:       oidObject(oid.IssuingDistributionPoint),
		Critical: true,
		Value:    []byte{0x30, 0x04, 0x83, 0x02, 0x06, 0x40},
	}}}
	reasons, ok := BuildTree(list).Resolve("issuingDistributionPoint.onlySomeReasons")
	if !ok {
		t.Fatal("onlySomeReasons projection is missing")
	}
	if reasons.Value != uint16(2) {
		t.Fatalf("onlySomeReasons value = %#v, want 2", reasons.Value)
	}
	want := map[string]bool{
		"unused":               false,
		"keyCompromise":        true,
		"cACompromise":         false,
		"affiliationChanged":   false,
		"superseded":           false,
		"cessationOfOperation": false,
		"certificateHold":      false,
		"privilegeWithdrawn":   false,
		"aACompromise":         false,
	}
	for name, wantValue := range want {
		child := reasons.Children[name]
		if child == nil || child.Value != wantValue {
			t.Errorf("%s = %#v, want %t", name, child, wantValue)
		}
	}
	if _, exists := reasons.Children["removeFromCRL"]; exists {
		t.Fatal("ReasonFlags projection contains CRLReason removeFromCRL")
	}
}

func oidObject(identifier string) zasn1.ObjectIdentifier {
	values := map[string]zasn1.ObjectIdentifier{
		oid.AuthorityKeyIdentifier:   {2, 5, 29, 35},
		oid.CRLNumber:                {2, 5, 29, 20},
		oid.CRLReason:                {2, 5, 29, 21},
		oid.InvalidityDate:           {2, 5, 29, 24},
		oid.DeltaCRLIndicator:        {2, 5, 29, 27},
		oid.IssuingDistributionPoint: {2, 5, 29, 28},
		oid.CertificateIssuer:        {2, 5, 29, 29},
		oid.FreshestCRL:              {2, 5, 29, 46},
		"1.2.3.4":                    {1, 2, 3, 4},
	}
	return values[identifier]
}
