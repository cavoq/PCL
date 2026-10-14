package x509asn1

import (
	"bytes"
	"strings"
)

// NamesMatch compares two DER-encoded Names by the rules of RFC 5280 Section
// 7.1: both have the same RDNs in the same order, each RDN has the same set
// of attribute types, and string attribute values match case-insensitively
// after insignificant whitespace is removed (RFC 4518), regardless of their
// string type. Other values must be identical. Names that do not parse match
// only byte for byte.
func NamesMatch(left, right []byte) bool {
	if bytes.Equal(left, right) {
		return true
	}
	leftName, err := ParseDistinguishedNameStrict(left)
	if err != nil {
		return false
	}
	rightName, err := ParseDistinguishedNameStrict(right)
	if err != nil || len(leftName.RDNs) != len(rightName.RDNs) {
		return false
	}
	for index := range leftName.RDNs {
		if !rdnsMatch(leftName.RDNs[index], rightName.RDNs[index]) {
			return false
		}
	}
	return true
}

// NameWithinSubtree reports whether name lies within the directoryName
// subtree base (RFC 5280 4.2.1.10): the RDNs of base are, in order, the first
// RDNs of name, compared with the Section 7.1 rules. A base without RDNs
// contains every name. Unparsable names are never within a subtree.
func NameWithinSubtree(name, base []byte) bool {
	parsedBase, err := ParseDistinguishedNameStrict(base)
	if err != nil {
		return false
	}
	parsedName, err := ParseDistinguishedNameStrict(name)
	if err != nil || len(parsedBase.RDNs) > len(parsedName.RDNs) {
		return false
	}
	for index, rdn := range parsedBase.RDNs {
		if !rdnsMatch(parsedName.RDNs[index], rdn) {
			return false
		}
	}
	return true
}

// NamesMatchOrText compares encoded names with NamesMatch, or their string
// forms when an encoding is unavailable, as for certificates constructed in
// memory rather than parsed.
func NamesMatchOrText(leftRaw, rightRaw []byte, leftText, rightText string) bool {
	if len(leftRaw) > 0 && len(rightRaw) > 0 {
		return NamesMatch(leftRaw, rightRaw)
	}
	return leftText == rightText
}

func rdnsMatch(left, right RelativeDistinguishedName) bool {
	if len(left.Attributes) != len(right.Attributes) {
		return false
	}
	matched := make([]bool, len(right.Attributes))
	for _, attribute := range left.Attributes {
		found := false
		for index, candidate := range right.Attributes {
			if !matched[index] && attributesMatch(attribute, candidate) {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func attributesMatch(left, right NameAttribute) bool {
	if left.OID != right.OID {
		return false
	}
	if isStringTag(left.Tag) && isStringTag(right.Tag) {
		return strings.EqualFold(prepareString(left.Value), prepareString(right.Value))
	}
	return left.Tag == right.Tag && bytes.Equal(left.RawValue, right.RawValue)
}

func isStringTag(tag int) bool {
	_, ok := stringTypesByTag[tag]
	return ok
}

// prepareString removes leading and trailing whitespace and collapses inner
// whitespace runs to one space, the insignificant space handling of RFC 4518.
func prepareString(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
