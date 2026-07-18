package zcrypto

import (
	"encoding/hex"
	"fmt"
	"strings"

	zpkix "github.com/zmap/zcrypto/x509/pkix"

	internalasn1 "github.com/cavoq/PCL/internal/asn1"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

// BuildName projects the exact DER Name when it is available. The parsed
// pkix.Name supplies only the compatibility display value; policy-visible RDN
// and attribute facts always come from raw DER.
func BuildName(name string, rawDER []byte, fallback zpkix.Name) *node.Node {
	if len(rawDER) == 0 {
		return BuildPkixName(name, fallback)
	}

	parsed, err := internalasn1.ParseDistinguishedNameStrict(rawDER)
	if err != nil {
		malformed := node.New(name, fallback.String())
		malformed.Children["raw"] = node.New("raw", append([]byte(nil), rawDER...))
		malformed.Children["malformed"] = node.New("malformed", true)
		return malformed
	}

	return buildDistinguishedNameNode(name, fallback.String(), parsed)
}

// BuildRawName projects a DER Name that has no corresponding pkix.Name, such
// as a directoryName GeneralName. Its display value is derived only for legacy
// scalar consumers; canonical consumers use rdns and attribute collections.
func BuildRawName(name string, rawDER []byte) *node.Node {
	parsed, err := internalasn1.ParseDistinguishedNameStrict(rawDER)
	if err != nil {
		malformed := node.New(name, "")
		malformed.Children["raw"] = node.New("raw", append([]byte(nil), rawDER...))
		malformed.Children["malformed"] = node.New("malformed", true)
		return malformed
	}
	return buildDistinguishedNameNode(name, distinguishedNameDisplay(parsed), parsed)
}

// BuildPkixName is the compatibility path for synthetic values that have no
// raw Name DER. It preserves RDN grouping and every value exposed by pkix, but
// correctly reports that their original encodings and raw bytes are unknown.
func BuildPkixName(name string, pkixName zpkix.Name) *node.Node {
	parsed := internalasn1.DistinguishedName{}
	for _, sourceRDN := range pkixName.ToRDNSequence() {
		rdn := internalasn1.RelativeDistinguishedName{}
		for _, sourceAttribute := range sourceRDN {
			rdn.Attributes = append(rdn.Attributes, internalasn1.NameAttribute{
				OID:      sourceAttribute.Type.String(),
				Encoding: "unknown",
				Value:    fmt.Sprint(sourceAttribute.Value),
			})
		}
		if len(rdn.Attributes) > 0 {
			parsed.RDNs = append(parsed.RDNs, rdn)
		}
	}
	if pkixName.OriginalRDNS == nil {
		commonNames := valuesExceptOne(pkixName.CommonNames, pkixName.CommonName)
		serialNumbers := valuesExceptOne(pkixName.SerialNumbers, pkixName.SerialNumber)
		appendSyntheticNameAttributes(&parsed, oid.AttributeCommonName, commonNames)
		appendSyntheticNameAttributes(&parsed, oid.AttributeSerialNumber, serialNumbers)
		appendSyntheticNameAttributes(&parsed, oid.AttributeGivenName, pkixName.GivenName)
		appendSyntheticNameAttributes(&parsed, oid.AttributeSurname, pkixName.Surname)
		appendSyntheticParsedAttributes(&parsed, pkixName.Names)
	}
	return buildDistinguishedNameNode(name, pkixName.String(), parsed)
}

func valuesExceptOne(values []string, excluded string) []string {
	if excluded == "" {
		return append([]string(nil), values...)
	}
	result := make([]string, 0, len(values))
	excludedOne := false
	for _, value := range values {
		if !excludedOne && value == excluded {
			excludedOne = true
			continue
		}
		result = append(result, value)
	}
	return result
}

func appendSyntheticNameAttributes(
	name *internalasn1.DistinguishedName,
	identifier string,
	values []string,
) {
	for _, value := range values {
		name.RDNs = append(name.RDNs, internalasn1.RelativeDistinguishedName{
			Attributes: []internalasn1.NameAttribute{{
				OID:      identifier,
				Encoding: "unknown",
				Value:    value,
			}},
		})
	}
}

func appendSyntheticParsedAttributes(
	name *internalasn1.DistinguishedName,
	attributes []zpkix.AttributeTypeAndValue,
) {
	existing := make(map[string]int)
	for _, rdn := range name.RDNs {
		for _, attribute := range rdn.Attributes {
			existing[syntheticAttributeKey(attribute.OID, attribute.Value)]++
		}
	}

	for _, attribute := range attributes {
		identifier := attribute.Type.String()
		value := fmt.Sprint(attribute.Value)
		key := syntheticAttributeKey(identifier, value)
		if existing[key] > 0 {
			existing[key]--
			continue
		}
		appendSyntheticNameAttributes(name, identifier, []string{value})
	}
}

func syntheticAttributeKey(identifier, value string) string {
	return identifier + "\x00" + value
}

func distinguishedNameDisplay(parsed internalasn1.DistinguishedName) string {
	rdns := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		attributes := make([]string, 0, len(rdn.Attributes))
		for _, attribute := range rdn.Attributes {
			name, known := oid.AttributeName(attribute.OID)
			if !known {
				name = attribute.OID
			}
			value := attribute.Value
			if attribute.Encoding == "unknown" {
				value = hex.EncodeToString(attribute.RawValue)
			}
			attributes = append(attributes, name+"="+value)
		}
		rdns = append(rdns, strings.Join(attributes, "+"))
	}
	return strings.Join(rdns, ",")
}

func buildDistinguishedNameNode(
	name string,
	displayValue string,
	parsed internalasn1.DistinguishedName,
) *node.Node {
	result := node.New(name, displayValue)
	if parsed.RawDER != nil {
		result.Children["raw"] = node.New("raw", append([]byte(nil), parsed.RawDER...))
	}

	rdns := node.New("rdns", nil)
	attributes := node.New("attributes", nil)
	result.Children["rdns"] = rdns
	result.Children["attributes"] = attributes

	attributeCollections := make(map[string]*node.Node)
	for rdnIndex, parsedRDN := range parsed.RDNs {
		rdn := node.New(fmt.Sprintf("%d", rdnIndex), len(parsedRDN.Attributes))
		if parsedRDN.RawDER != nil {
			rdn.Children["raw"] = node.New("raw", append([]byte(nil), parsedRDN.RawDER...))
		}
		rdnAttributes := node.New("attributes", nil)
		rdn.Children["attributes"] = rdnAttributes

		for attributeIndex, parsedAttribute := range parsedRDN.Attributes {
			attribute := buildNameAttributeNode(attributeIndex, parsedAttribute)
			rdnAttributes.AddElement(attribute)

			collection := attributeCollections[parsedAttribute.OID]
			if collection == nil {
				collectionName, known := oid.AttributeName(parsedAttribute.OID)
				if !known {
					collectionName = parsedAttribute.OID
				}
				collection = node.New(collectionName, attribute.Value)
				collection.Children["oid"] = node.New("oid", parsedAttribute.OID)
				attributeCollections[parsedAttribute.OID] = collection
				attributes.Children[parsedAttribute.OID] = collection
				result.Children[parsedAttribute.OID] = collection
				if known {
					attributes.Children[collectionName] = collection
					result.Children[collectionName] = collection
				}
			}
			collection.AddElement(attribute)
		}

		rdns.AddElement(rdn)
	}

	return result
}

func buildNameAttributeNode(index int, parsed internalasn1.NameAttribute) *node.Node {
	value := any(parsed.Value)
	if parsed.Encoding == "unknown" && parsed.RawDER != nil {
		value = append([]byte(nil), parsed.RawValue...)
	}

	attribute := node.New(fmt.Sprintf("%d", index), value)
	attribute.Children["value"] = node.New("value", value)
	attribute.Children["oid"] = node.New("oid", parsed.OID)
	attribute.Children["tag"] = node.New("tag", parsed.Tag)
	attribute.Children["encoding"] = node.New("encoding", parsed.Tag)
	attribute.Children["encodingName"] = node.New("encodingName", parsed.Encoding)
	attribute.Children["raw"] = node.New("raw", append([]byte(nil), parsed.RawDER...))
	attribute.Children["rawValue"] = node.New("rawValue", append([]byte(nil), parsed.RawValue...))
	if friendlyName, known := oid.AttributeName(parsed.OID); known {
		attribute.Children["name"] = node.New("name", friendlyName)
	}
	return attribute
}
