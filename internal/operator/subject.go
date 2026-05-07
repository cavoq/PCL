package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
)

// NoDuplicateAttributes checks that subject DN does not contain
// duplicate AttributeTypeAndValue instances per CABF BR 7.1.4.1
type NoDuplicateAttributes struct{}

// singleInstanceOIDs maps OID string → attribute name for attributes that must
// appear at most once per CABF BR 7.1.4.1.
var singleInstanceOIDs = map[string]string{
	"2.5.4.3":                  "commonName",
	"2.5.4.4":                  "surname",
	"2.5.4.5":                  "serialNumber",
	"2.5.4.6":                  "countryName",
	"2.5.4.7":                  "localityName",
	"2.5.4.8":                  "stateOrProvinceName",
	"2.5.4.10":                 "organizationName",
	"2.5.4.15":                 "businessCategory",
	"2.5.4.42":                 "givenName",
	"2.5.4.97":                 "organizationIdentifier",
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionLocality",
	"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionStateOrProvince",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionCountry",
}

// exemptOIDs lists attributes that may appear multiple times (domainComponent,
// streetAddress, and the deprecated organizationalUnitName).
var exemptOIDs = map[string]bool{
	"0.9.2342.19200300.100.1.25": true,
	"2.5.4.9":                   true,
	"2.5.4.11":                  true,
}

// nameToOID maps friendly attribute names to their OID strings for cases where
// the node carries no explicit OID child.
var nameToOID = map[string]string{
	"commonName":             "2.5.4.3",
	"surname":                "2.5.4.4",
	"serialNumber":           "2.5.4.5",
	"countryName":            "2.5.4.6",
	"localityName":           "2.5.4.7",
	"stateOrProvinceName":    "2.5.4.8",
	"organizationName":       "2.5.4.10",
	"businessCategory":       "2.5.4.15",
	"givenName":              "2.5.4.42",
	"organizationIdentifier": "2.5.4.97",
}

func (NoDuplicateAttributes) Name() string { return "noDuplicateAttributes" }

func (NoDuplicateAttributes) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	foundOIDs := make(map[string]int)

	for childName, child := range n.Children {
		oidNode := child.Children["oid"]
		var attrOID string
		if oidNode != nil && oidNode.Value != nil {
			attrOID = fmt.Sprintf("%v", oidNode.Value)
		}

		if attrOID == "" {
			attrOID = nameToOID[childName]
		}

		if attrOID == "" || exemptOIDs[attrOID] {
			continue
		}

		if singleInstanceOIDs[attrOID] != "" {
			foundOIDs[attrOID]++
			if foundOIDs[attrOID] > 1 {
				return false, nil
			}
		}
	}

	return true, nil
}
