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

	foundOIDs := make(map[string]int)

	for childName, child := range n.Children {
		if child == nil {
			continue
		}
		oidNode := child.Children["oid"]
		var attrOID string
		if oidNode != nil && oidNode.Value != nil {
			attrOID = fmt.Sprintf("%v", oidNode.Value)
		}

		if attrOID == "" {
			attrOID, _ = oid.AttributeOID(child.Name)
		}
		if attrOID == "" {
			attrOID, _ = oid.AttributeOID(childName)
		}

		if _, singleInstance := singleInstanceAttributeOIDs[attrOID]; !singleInstance {
			continue
		}
		foundOIDs[attrOID]++
		if foundOIDs[attrOID] > 1 {
			return false, nil
		}
	}

	return true, nil
}
