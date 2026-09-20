package tests

import (
	"bytes"
	"fmt"
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

	classified, err := parseActiveRuleClassifications(coverage)
	if err != nil {
		t.Fatalf("parse active-rule coverage table: %v", err)
	}

	activeIDs := make(map[string]struct{}, len(active.Rules))
	for _, candidate := range active.Rules {
		activeIDs[candidate.ID] = struct{}{}
		count := classified[candidate.ID]
		switch {
		case count == 0:
			t.Errorf("active rule %q is missing from the active-rule coverage table", candidate.ID)
		case count > 1:
			t.Errorf("active rule %q is classified %d times; want exactly once", candidate.ID, count)
		}
	}
	for identifier := range classified {
		if _, active := activeIDs[identifier]; !active {
			t.Errorf("coverage table classifies stale or inactive rule %q", identifier)
		}
	}

	for _, evidence := range []string{
		"vector_coverage_test.go",
		"deterministic_pki_test.go",
		"extension_parser_test.go",
		"status_assessment_test.go",
		"acquisition_test.go",
		"extensions_test.go",
		"integration_test.go",
	} {
		if !strings.Contains(coverage, evidence) {
			t.Errorf("coverage matrix does not link executable evidence %q", evidence)
		}
	}
}

func parseActiveRuleClassifications(document string) (map[string]int, error) {
	const (
		startHeading = "## Active rule classification"
		endHeading   = "## Executable evidence"
	)
	start := strings.Index(document, startHeading)
	end := strings.Index(document, endHeading)
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("missing or out-of-order coverage headings")
	}

	classifications := make(map[string]int)
	for _, line := range strings.Split(document[start:end], "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "|---") ||
			strings.HasPrefix(line, "| Area ") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) < 5 {
			return nil, fmt.Errorf("malformed coverage row %q", line)
		}
		classification := strings.TrimSpace(columns[2])
		if classification != "Covered" && classification != "Partial" {
			return nil, fmt.Errorf("unsupported classification %q in row %q", classification, line)
		}
		identifiers := backtickValues(columns[3])
		if len(identifiers) == 0 {
			return nil, fmt.Errorf("coverage row has no rule identifiers: %q", line)
		}
		for _, identifier := range identifiers {
			classifications[identifier]++
		}
	}
	return classifications, nil
}

func backtickValues(value string) []string {
	var values []string
	for {
		start := strings.IndexByte(value, '`')
		if start < 0 {
			return values
		}
		value = value[start+1:]
		end := strings.IndexByte(value, '`')
		if end < 0 {
			return values
		}
		values = append(values, value[:end])
		value = value[end+1:]
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
