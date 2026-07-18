package zcrypto

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cavoq/PCL/internal/node"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	extensionSchemaOCSPMethodOID      = stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	extensionSchemaCAIssuersMethodOID = stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

func TestParseAIAStrictNodeSchema(t *testing.T) {
	n, err := ParseAIAStrict(buildExtensionSchemaAIA())
	if err != nil {
		t.Fatalf("ParseAIAStrict() error = %v", err)
	}

	assertExtensionSchemaNode(t, n, "authorityInfoAccess", nil,
		"accessDescriptions", "containsCaIssuers", "containsOCSP", "count", "empty")
	assertExtensionSchemaValue(t, n, "count", 2)
	assertExtensionSchemaValue(t, n, "empty", false)
	assertExtensionSchemaValue(t, n, "containsOCSP", true)
	assertExtensionSchemaValue(t, n, "containsCaIssuers", true)

	descriptions := requireExtensionSchemaChild(t, n, "accessDescriptions")
	assertExtensionSchemaNode(t, descriptions, "accessDescriptions", nil, "0", "1")

	assertExtensionSchemaAccessDescription(
		t,
		requireExtensionSchemaChild(t, descriptions, "0"),
		"0",
		extensionSchemaOCSPMethodOID.String(),
		"http://ocsp.example.test",
	)
	assertExtensionSchemaAccessDescription(
		t,
		requireExtensionSchemaChild(t, descriptions, "1"),
		"1",
		extensionSchemaCAIssuersMethodOID.String(),
		"https://issuer.example.test/ca.der",
	)
}

func TestParseCRLDPStrictGeneralNamesNodeSchema(t *testing.T) {
	n, err := ParseCRLDPStrict(buildExtensionSchemaCRLDP(nil, true))
	if err != nil {
		t.Fatalf("ParseCRLDPStrict() error = %v", err)
	}

	assertExtensionSchemaNode(t, n, "cRLDistributionPoints", nil,
		"count", "distributionPoints", "empty")
	assertExtensionSchemaValue(t, n, "count", 1)
	assertExtensionSchemaValue(t, n, "empty", false)

	distributionPoints := requireExtensionSchemaChild(t, n, "distributionPoints")
	assertExtensionSchemaNode(t, distributionPoints, "distributionPoints", nil, "0")
	distributionPoint := requireExtensionSchemaChild(t, distributionPoints, "0")
	assertExtensionSchemaNode(t, distributionPoint, "0", nil,
		"cRLIssuer", "distributionPoint", "hasCRLIssuer", "hasFullName", "hasReasons")
	assertExtensionSchemaValue(t, distributionPoint, "hasFullName", true)
	assertExtensionSchemaValue(t, distributionPoint, "hasReasons", false)
	assertExtensionSchemaValue(t, distributionPoint, "hasCRLIssuer", true)

	name := requireExtensionSchemaChild(t, distributionPoint, "distributionPoint")
	assertExtensionSchemaNode(t, name, "distributionPoint", nil, "fullName")
	fullName := requireExtensionSchemaChild(t, name, "fullName")
	assertExtensionSchemaNode(t, fullName, "fullName", nil, "count", "generalNames")
	assertExtensionSchemaValue(t, fullName, "count", 1)
	generalNames := requireExtensionSchemaChild(t, fullName, "generalNames")
	assertExtensionSchemaNode(t, generalNames, "generalNames", nil, "0")
	uri := requireExtensionSchemaChild(t, generalNames, "0")
	assertExtensionSchemaNode(t, uri, "0", "http://crl.example.test/root.crl",
		"raw", "rawValue", "scheme", "tag", "type", "value")
	assertExtensionSchemaValue(t, uri, "type", "uniformResourceIdentifier")
	assertExtensionSchemaValue(t, uri, "tag", 6)
	assertExtensionSchemaValue(t, uri, "value", "http://crl.example.test/root.crl")
	assertExtensionSchemaValue(t, uri, "scheme", "http")

	issuer := requireExtensionSchemaChild(t, distributionPoint, "cRLIssuer")
	assertExtensionSchemaNode(t, issuer, "cRLIssuer", nil, "0", "count", "present")
	assertExtensionSchemaValue(t, issuer, "count", 1)
	assertExtensionSchemaValue(t, issuer, "present", true)
	issuerName := requireExtensionSchemaChild(t, issuer, "0")
	assertExtensionSchemaNode(t, issuerName, "0", "issuer.example.test",
		"raw", "rawValue", "tag", "type", "value")
	assertExtensionSchemaValue(t, issuerName, "type", "dNSName")
	assertExtensionSchemaValue(t, issuerName, "tag", 2)
	assertExtensionSchemaValue(t, issuerName, "value", "issuer.example.test")
}

func TestCompatibilityExtensionWrappersMalformedAndEmptySchema(t *testing.T) {
	tests := []struct {
		name     string
		rootName string
		parse    func([]byte) *node.Node
	}{
		{name: "AIA", rootName: "authorityInfoAccess", parse: ParseAIA},
		{name: "CRLDP", rootName: "cRLDistributionPoints", parse: ParseCRLDP},
	}

	for _, test := range tests {
		t.Run(test.name+"/malformed", func(t *testing.T) {
			n := test.parse([]byte{0x01, 0x01, 0x00})
			assertExtensionSchemaNode(t, n, test.rootName, nil, "malformed")
			assertExtensionSchemaValue(t, n, "malformed", true)
		})

		t.Run(test.name+"/empty", func(t *testing.T) {
			n := test.parse([]byte{0x30, 0x00})
			assertExtensionSchemaNode(t, n, test.rootName, nil, "empty", "malformed")
			assertExtensionSchemaValue(t, n, "malformed", true)
			assertExtensionSchemaValue(t, n, "empty", true)
		})
	}
}

func TestParseCRLDPStrictReasonFlagsRFC5280BitMapping(t *testing.T) {
	reasonNames := []string{
		"unused",
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"privilegeWithdrawn",
		"aACompromise",
	}

	for bit, reasonName := range reasonNames {
		t.Run(reasonName, func(t *testing.T) {
			encodedReasons, value, unusedBits := extensionSchemaSingleReasonBit(bit)
			n, err := ParseCRLDPStrict(buildExtensionSchemaCRLDP(encodedReasons, false))
			if err != nil {
				t.Fatalf("ParseCRLDPStrict() error = %v", err)
			}

			distributionPoints := requireExtensionSchemaChild(t, n, "distributionPoints")
			distributionPoint := requireExtensionSchemaChild(t, distributionPoints, "0")
			assertExtensionSchemaValue(t, distributionPoint, "hasReasons", true)
			reasons := requireExtensionSchemaChild(t, distributionPoint, "reasons")
			assertExtensionSchemaNode(t, reasons, "reasons", nil,
				reasonName, "present", "raw", "unusedBits", "value")
			assertExtensionSchemaValue(t, reasons, "present", true)
			assertExtensionSchemaValue(t, reasons, "unusedBits", unusedBits)
			assertExtensionSchemaValue(t, reasons, reasonName, true)
			assertExtensionSchemaBytes(t, requireExtensionSchemaChild(t, reasons, "raw").Value, encodedReasons)
			assertExtensionSchemaBytes(t, requireExtensionSchemaChild(t, reasons, "value").Value, value)

			if _, exists := reasons.Children["removeFromCRL"]; exists {
				t.Fatal("DistributionPoint ReasonFlags must not contain CRLReason removeFromCRL")
			}
		})
	}
}

func buildExtensionSchemaAIA() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		addExtensionSchemaAccessDescription(
			builder,
			extensionSchemaOCSPMethodOID,
			"http://ocsp.example.test",
		)
		addExtensionSchemaAccessDescription(
			builder,
			extensionSchemaCAIssuersMethodOID,
			"https://issuer.example.test/ca.der",
		)
	})
	return builder.BytesOrPanic()
}

func addExtensionSchemaAccessDescription(
	builder *cryptobyte.Builder,
	method stdasn1.ObjectIdentifier,
	uri string,
) {
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1ObjectIdentifier(method)
		builder.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte(uri))
		})
	})
}

func buildExtensionSchemaCRLDP(encodedReasons []byte, includeCRLIssuer bool) []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
		builder.AddASN1(cryptobyte_asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
			builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
				builder.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
					builder.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte("http://crl.example.test/root.crl"))
					})
				})
			})
			if encodedReasons != nil {
				builder.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(builder *cryptobyte.Builder) {
					builder.AddBytes(encodedReasons)
				})
			}
			if includeCRLIssuer {
				builder.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific().Constructed(), func(builder *cryptobyte.Builder) {
					builder.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(builder *cryptobyte.Builder) {
						builder.AddBytes([]byte("issuer.example.test"))
					})
				})
			}
		})
	})
	return builder.BytesOrPanic()
}

func extensionSchemaSingleReasonBit(bit int) (encoded, value []byte, unusedBits int) {
	byteCount := bit/8 + 1
	unusedBits = byteCount*8 - bit - 1
	value = make([]byte, byteCount)
	value[bit/8] = 1 << (7 - (bit % 8))
	encoded = append([]byte{byte(unusedBits)}, value...)
	return encoded, value, unusedBits
}

func assertExtensionSchemaAccessDescription(
	t *testing.T,
	description *node.Node,
	name string,
	method string,
	uri string,
) {
	t.Helper()
	assertExtensionSchemaNode(t, description, name, nil, "accessLocation", "accessMethod")
	assertExtensionSchemaValue(t, description, "accessMethod", method)
	location := requireExtensionSchemaChild(t, description, "accessLocation")
	assertExtensionSchemaNode(t, location, "accessLocation", uri,
		"raw", "rawValue", "scheme", "tag", "type", "value")
	assertExtensionSchemaValue(t, location, "type", "uniformResourceIdentifier")
	assertExtensionSchemaValue(t, location, "tag", 6)
	assertExtensionSchemaValue(t, location, "value", uri)
	wantScheme, _, ok := strings.Cut(uri, ":")
	if !ok {
		t.Fatalf("test URI %q has no scheme", uri)
	}
	assertExtensionSchemaValue(t, location, "scheme", wantScheme)
}

func assertExtensionSchemaNode(
	t *testing.T,
	n *node.Node,
	wantName string,
	wantValue any,
	wantChildren ...string,
) {
	t.Helper()
	if n == nil {
		t.Fatalf("node %q is nil", wantName)
	}
	if n.Name != wantName {
		t.Errorf("node name = %q, want %q", n.Name, wantName)
	}
	if !reflect.DeepEqual(n.Value, wantValue) {
		t.Errorf("node %q value = %#v, want %#v", wantName, n.Value, wantValue)
	}

	gotChildren := extensionSchemaChildKeys(n)
	sort.Strings(wantChildren)
	if !reflect.DeepEqual(gotChildren, wantChildren) {
		t.Errorf("node %q child keys = %v, want %v", wantName, gotChildren, wantChildren)
	}
}

func assertExtensionSchemaValue(t *testing.T, parent *node.Node, childName string, want any) {
	t.Helper()
	child := requireExtensionSchemaChild(t, parent, childName)
	if child.Name != childName {
		t.Errorf("child %q node name = %q", childName, child.Name)
	}
	if !reflect.DeepEqual(child.Value, want) {
		t.Errorf("child %q value = %#v, want %#v", childName, child.Value, want)
	}
	if len(child.Children) != 0 {
		t.Errorf("scalar child %q has nested children %v", childName, extensionSchemaChildKeys(child))
	}
}

func assertExtensionSchemaBytes(t *testing.T, got any, want []byte) {
	t.Helper()
	var gotBytes []byte
	switch value := got.(type) {
	case []byte:
		gotBytes = value
	case cryptobyte.String:
		gotBytes = []byte(value)
	default:
		t.Fatalf("byte node value has type %T", got)
	}
	if !bytes.Equal(gotBytes, want) {
		t.Errorf("byte node value = %x, want %x", gotBytes, want)
	}
}

func requireExtensionSchemaChild(t *testing.T, parent *node.Node, name string) *node.Node {
	t.Helper()
	if parent == nil {
		t.Fatalf("cannot find child %q on nil parent", name)
	}
	child, ok := parent.Children[name]
	if !ok || child == nil {
		t.Fatalf("node %q missing child %q", parent.Name, name)
	}
	return child
}

func extensionSchemaChildKeys(n *node.Node) []string {
	keys := make([]string, 0, len(n.Children))
	for name := range n.Children {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}
