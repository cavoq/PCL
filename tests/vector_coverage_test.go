package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/policy"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

func TestRFC5280CoverageClassifiesEveryActiveRule(t *testing.T) {
	policyPath := filepath.Join("..", "policies", "RFC5280.yaml")
	coveragePath := filepath.Join("..", "policies", "RFC5280-COVERAGE.md")

	active, err := policy.ParseFile(policyPath)
	if err != nil {
		t.Fatalf("parse active RFC 5280 policy: %v", err)
	}
	coverageBytes, err := os.ReadFile(coveragePath)
	if err != nil {
		t.Fatalf("read RFC 5280 coverage matrix: %v", err)
	}
	coverage := string(coverageBytes)

	for _, candidate := range active.Rules {
		needle := "`" + candidate.ID + "`"
		_, found := classifiedMarkdownLineContaining(coverage, needle)
		if !found {
			if strings.Contains(coverage, needle) {
				t.Errorf("active rule %q is mentioned but not explicitly classified as Covered, Partial, or Not active", candidate.ID)
			} else {
				t.Errorf("active rule %q is missing from the coverage matrix", candidate.ID)
			}
		}
	}

	for _, evidence := range []string{
		"vector_coverage_test.go",
		"deterministic_pki_test.go",
		"extension_parser_test.go",
	} {
		if !strings.Contains(coverage, evidence) {
			t.Errorf("coverage matrix does not link executable evidence %q", evidence)
		}
	}
}

func TestMalformedProfileExtensionDERVectors(t *testing.T) {
	vectors := []struct {
		name       string
		identifier string
		objectID   zasn1.ObjectIdentifier
		value      []byte
	}{
		{name: "key usage", identifier: oid.KeyUsage, objectID: zasn1.ObjectIdentifier{2, 5, 29, 15}, value: []byte{0x03, 0x02, 0x08, 0x00}},
		{name: "basic constraints", identifier: oid.BasicConstraints, objectID: zasn1.ObjectIdentifier{2, 5, 29, 19}, value: []byte{0x30, 0x01, 0x00}},
		{name: "name constraints", identifier: oid.NameConstraints, objectID: zasn1.ObjectIdentifier{2, 5, 29, 30}, value: []byte{0x30, 0x00}},
		{name: "CRL distribution points", identifier: oid.CRLDistributionPoints, objectID: zasn1.ObjectIdentifier{2, 5, 29, 31}, value: []byte{0x30, 0x00}},
		{name: "policy mappings", identifier: oid.PolicyMappings, objectID: zasn1.ObjectIdentifier{2, 5, 29, 33}, value: []byte{0x30, 0x00}},
		{name: "policy constraints", identifier: oid.PolicyConstraints, objectID: zasn1.ObjectIdentifier{2, 5, 29, 36}, value: []byte{0x30, 0x00}},
		{name: "extended key usage", identifier: oid.ExtendedKeyUsage, objectID: zasn1.ObjectIdentifier{2, 5, 29, 37}, value: []byte{0x30, 0x00}},
		{name: "inhibit anyPolicy", identifier: oid.InhibitAnyPolicy, objectID: zasn1.ObjectIdentifier{2, 5, 29, 54}, value: []byte{0x02, 0x00}},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			tree := certzcrypto.BuildTree(&x509.Certificate{Extensions: []pkix.Extension{{
				Id:       vector.objectID,
				Critical: true,
				Value:    append([]byte(nil), vector.value...),
			}}})

			extension, ok := tree.Resolve("certificate.extensions." + vector.identifier)
			if !ok {
				t.Fatal("extension node is missing")
			}
			malformed, ok := extension.Resolve("malformed")
			if !ok || malformed.Value != true {
				t.Fatalf("malformed marker = %#v, want true", malformed)
			}
			raw, ok := extension.Resolve("value")
			if !ok || !bytes.Equal(raw.Value.([]byte), vector.value) {
				t.Fatalf("raw extension value = %#v, want %x", raw, vector.value)
			}

			assertCriticalExtensionRejected(t, tree)
		})
	}
}

func assertCriticalExtensionRejected(t *testing.T, tree *node.Node) {
	t.Helper()
	accepted, err := operator.DefaultRegistry().Evaluate(
		"noUnknownCriticalExtensions",
		tree,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("evaluate critical extension registry: %v", err)
	}
	if accepted {
		t.Fatal("malformed critical extension was accepted as processed")
	}
}

func classifiedMarkdownLineContaining(document, needle string) (string, bool) {
	for _, line := range strings.Split(document, "\n") {
		if strings.Contains(line, needle) && containsCoverageClassification(line) {
			return line, true
		}
	}
	return "", false
}

func containsCoverageClassification(line string) bool {
	return strings.Contains(line, "Covered") ||
		strings.Contains(line, "Partial") ||
		strings.Contains(line, "Not active")
}
