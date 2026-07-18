package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/oid"
)

// NoDuplicateAttributes checks that subject DN does not contain
// duplicate AttributeTypeAndValue instances per CABF BR 7.1.4.1
type NoDuplicateAttributes struct{}

// singleInstanceAttributeOIDs is the CABF BR 7.1.4.1 policy decision. The
// identifiers and projected attribute names remain owned by package oid.
var singleInstanceAttributeOIDs = map[string]struct{}{
	oid.AttributeCommonName:                  {},
	oid.AttributeSurname:                     {},
	oid.AttributeSerialNumber:                {},
	oid.AttributeCountryName:                 {},
	oid.AttributeLocalityName:                {},
	oid.AttributeStateOrProvinceName:         {},
	oid.AttributeOrganizationName:            {},
	oid.AttributeBusinessCategory:            {},
	oid.AttributeGivenName:                   {},
	oid.AttributeOrganizationIdentifier:      {},
	oid.AttributeJurisdictionLocality:        {},
	oid.AttributeJurisdictionStateOrProvince: {},
	oid.AttributeJurisdictionCountry:         {},
}

func (NoDuplicateAttributes) Name() string { return "noDuplicateAttributes" }

func (NoDuplicateAttributes) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if malformed := n.Children["malformed"]; malformed != nil && malformed.Value == true {
		return false, nil
	}

	foundOIDs := make(map[string]int)
	if attributes := n.Children["attributes"]; attributes != nil {
		for _, collection := range node.CollectionElements(attributes) {
			for _, attribute := range node.CollectionElements(collection) {
				if duplicateSingleInstanceAttribute(attribute, "", foundOIDs) {
					return false, nil
				}
			}
		}
		return true, nil
	}

	for childName, child := range n.Children {
		if duplicateSingleInstanceAttribute(child, childName, foundOIDs) {
			return false, nil
		}
	}

	return true, nil
}

func duplicateSingleInstanceAttribute(
	attribute *node.Node,
	childName string,
	foundOIDs map[string]int,
) bool {
	if attribute == nil {
		return false
	}

	var attrOID string
	if oidNode := attribute.Children["oid"]; oidNode != nil && oidNode.Value != nil {
		attrOID = fmt.Sprintf("%v", oidNode.Value)
	}
	if attrOID == "" {
		attrOID, _ = oid.AttributeOID(attribute.Name)
	}
	if attrOID == "" {
		attrOID, _ = oid.AttributeOID(childName)
	}
	if _, singleInstance := singleInstanceAttributeOIDs[attrOID]; !singleInstance {
		return false
	}
	foundOIDs[attrOID]++
	return foundOIDs[attrOID] > 1
}
