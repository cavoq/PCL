package x509ext

// CRLDistributionPointNameKind identifies the selected DistributionPointName
// alternative. The empty value means the optional field was absent.
type CRLDistributionPointNameKind string

const (
	CRLDistributionPointNameAbsent   CRLDistributionPointNameKind = ""
	CRLDistributionPointNameFullName CRLDistributionPointNameKind = "fullName"
	CRLDistributionPointNameRelative CRLDistributionPointNameKind = "nameRelativeToCRLIssuer"
)

// CRLDistributionPointsFacts is the typed adapter boundary used by
// certificate-profile predicates. It deliberately keeps profile dependencies
// out of the DER parser while retaining enough structure to enforce them.
type CRLDistributionPointsFacts struct {
	DistributionPoints []CRLDistributionPointFacts
}

// CRLDistributionPointFacts describes one distribution point of a CRL
// Distribution Points extension for profile checks.
type CRLDistributionPointFacts struct {
	DistributionPointPresent  bool
	DistributionPointNameKind CRLDistributionPointNameKind
	FullNameGeneralNameTags   []int
	ReasonsPresent            bool
	ReasonMask                ReasonMask
	CRLIssuerGeneralNameTags  []int
}

// DecodeCRLDistributionPointsStrict returns strictly decoded structural facts
// without applying RFC 5280 profile dependencies such as the cRLIssuer name
// form restriction or the relative-name single-issuer rule.
func DecodeCRLDistributionPointsStrict(extValue []byte) (CRLDistributionPointsFacts, error) {
	decoded, err := DecodeDistributionPoints(extValue)
	if err != nil {
		return CRLDistributionPointsFacts{}, err
	}

	facts := CRLDistributionPointsFacts{
		DistributionPoints: make([]CRLDistributionPointFacts, 0, len(decoded)),
	}
	for _, distributionPoint := range decoded {
		pointFacts := CRLDistributionPointFacts{
			DistributionPointPresent: distributionPoint.Name != nil,
			ReasonsPresent:           distributionPoint.Reasons != nil,
		}
		if distributionPoint.Name != nil {
			switch distributionPoint.Name.Kind {
			case DistributionPointNameFullName:
				pointFacts.DistributionPointNameKind = CRLDistributionPointNameFullName
				pointFacts.FullNameGeneralNameTags = generalNameTags(
					distributionPoint.Name.FullName,
				)
			case DistributionPointNameRelative:
				pointFacts.DistributionPointNameKind = CRLDistributionPointNameRelative
			}
		}
		if distributionPoint.Reasons != nil {
			pointFacts.ReasonMask = distributionPoint.Reasons.Mask
		}
		pointFacts.CRLIssuerGeneralNameTags = generalNameTags(distributionPoint.CRLIssuer)
		facts.DistributionPoints = append(facts.DistributionPoints, pointFacts)
	}
	return facts, nil
}

func generalNameTags(names []GeneralName) []int {
	if names == nil {
		return nil
	}
	tags := make([]int, 0, len(names))
	for _, name := range names {
		tags = append(tags, name.Tag)
	}
	return tags
}
