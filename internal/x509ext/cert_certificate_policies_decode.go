package x509ext

import (
	stdasn1 "encoding/asn1"
	"fmt"

	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CertificatePolicies is a decoded Certificate Policies extension.
type CertificatePolicies struct {
	Policies []PolicyInformation
	RawDER   []byte
}

// PolicyInformation is one policy of a Certificate Policies extension.
type PolicyInformation struct {
	OID        string
	Qualifiers []PolicyQualifier
}

// PolicyQualifierKind identifies the RFC 5280 policy qualifier types PCL
// decodes.
type PolicyQualifierKind uint8

const (
	PolicyQualifierUnknown PolicyQualifierKind = iota
	PolicyQualifierCPS
	PolicyQualifierUserNotice
)

// PolicyQualifier is one qualifier of a policy. CPSURI or UserNotice is
// set according to Kind.
type PolicyQualifier struct {
	OID        string
	Kind       PolicyQualifierKind
	CPSURI     string
	UserNotice *UserNotice
	Raw        cryptobyte.String
}

// UserNotice is the user notice policy qualifier.
type UserNotice struct {
	Reference    *NoticeReference
	ExplicitText *DisplayText
}

// NoticeReference is the optional notice reference of a user notice.
type NoticeReference struct {
	Organization DisplayText
	Numbers      []int64
}

// DisplayText is a DisplayText value with the ASN.1 string type it was
// encoded with.
type DisplayText struct {
	Value string
	Tag   cryptobyte_asn1.Tag
}

// DecodeCertificatePolicies decodes a Certificate Policies extension value,
// including its policy qualifiers.
func DecodeCertificatePolicies(extValue []byte) (CertificatePolicies, error) {
	input := cryptobyte.String(extValue)
	var encodedPolicies cryptobyte.String
	if !input.ReadASN1(&encodedPolicies, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return CertificatePolicies{}, fmt.Errorf("invalid CertificatePolicies sequence")
	}
	if encodedPolicies.Empty() {
		return CertificatePolicies{}, fmt.Errorf("CertificatePolicies must not be empty")
	}

	decoded := CertificatePolicies{RawDER: append([]byte(nil), extValue...)}
	seenPolicyIdentifiers := make(map[string]struct{})
	for policyIndex := 0; !encodedPolicies.Empty(); policyIndex++ {
		policy, err := decodePolicyInformation(&encodedPolicies, policyIndex)
		if err != nil {
			return CertificatePolicies{}, err
		}
		if _, duplicate := seenPolicyIdentifiers[policy.OID]; duplicate {
			return CertificatePolicies{}, fmt.Errorf(
				"duplicate policyIdentifier %s in PolicyInformation %d",
				policy.OID,
				policyIndex,
			)
		}
		if policy.OID == oid.AnyPolicy {
			for _, qualifier := range policy.Qualifiers {
				if qualifier.Kind == PolicyQualifierUnknown {
					return CertificatePolicies{}, fmt.Errorf(
						"unsupported qualifier %s on anyPolicy in PolicyInformation %d",
						qualifier.OID,
						policyIndex,
					)
				}
			}
		}
		seenPolicyIdentifiers[policy.OID] = struct{}{}
		decoded.Policies = append(decoded.Policies, policy)
	}
	return decoded, nil
}

func decodePolicyInformation(input *cryptobyte.String, policyIndex int) (PolicyInformation, error) {
	var encodedPolicy cryptobyte.String
	if !input.ReadASN1(&encodedPolicy, cryptobyte_asn1.SEQUENCE) {
		return PolicyInformation{}, fmt.Errorf("invalid PolicyInformation %d", policyIndex)
	}

	var policyID stdasn1.ObjectIdentifier
	if !encodedPolicy.ReadASN1ObjectIdentifier(&policyID) {
		return PolicyInformation{}, fmt.Errorf("invalid policyIdentifier in PolicyInformation %d", policyIndex)
	}
	decoded := PolicyInformation{OID: policyID.String()}
	if encodedPolicy.Empty() {
		return decoded, nil
	}

	var encodedQualifiers cryptobyte.String
	if !encodedPolicy.ReadASN1(&encodedQualifiers, cryptobyte_asn1.SEQUENCE) ||
		!encodedPolicy.Empty() || encodedQualifiers.Empty() {
		return PolicyInformation{}, fmt.Errorf("invalid policyQualifiers in PolicyInformation %d", policyIndex)
	}

	for qualifierIndex := 0; !encodedQualifiers.Empty(); qualifierIndex++ {
		qualifier, err := decodePolicyQualifier(&encodedQualifiers, policyIndex, qualifierIndex)
		if err != nil {
			return PolicyInformation{}, err
		}
		decoded.Qualifiers = append(decoded.Qualifiers, qualifier)
	}
	return decoded, nil
}

func decodePolicyQualifier(input *cryptobyte.String, policyIndex, qualifierIndex int) (PolicyQualifier, error) {
	var encodedQualifier cryptobyte.String
	if !input.ReadASN1(&encodedQualifier, cryptobyte_asn1.SEQUENCE) {
		return PolicyQualifier{}, fmt.Errorf(
			"invalid PolicyQualifierInfo %d in PolicyInformation %d",
			qualifierIndex,
			policyIndex,
		)
	}

	var qualifierID stdasn1.ObjectIdentifier
	if !encodedQualifier.ReadASN1ObjectIdentifier(&qualifierID) {
		return PolicyQualifier{}, fmt.Errorf("invalid policyQualifierId in PolicyInformation %d", policyIndex)
	}

	var value cryptobyte.String
	var valueTag cryptobyte_asn1.Tag
	if !encodedQualifier.ReadAnyASN1(&value, &valueTag) || !encodedQualifier.Empty() {
		return PolicyQualifier{}, fmt.Errorf("invalid qualifier value in PolicyInformation %d", policyIndex)
	}

	decoded := PolicyQualifier{OID: qualifierID.String()}
	switch decoded.OID {
	case oid.PolicyQualifierCPS:
		if valueTag != cryptobyte_asn1.IA5String {
			return PolicyQualifier{}, fmt.Errorf(
				"CPS qualifier in PolicyInformation %d is not IA5String",
				policyIndex,
			)
		}
		if value.Empty() {
			return PolicyQualifier{}, fmt.Errorf("invalid CPS qualifier in PolicyInformation %d", policyIndex)
		}
		for _, character := range value {
			if character > 0x7f {
				return PolicyQualifier{}, fmt.Errorf(
					"non-IA5 character in CPS qualifier in PolicyInformation %d",
					policyIndex,
				)
			}
		}
		decoded.Kind = PolicyQualifierCPS
		decoded.CPSURI = string(value)

	case oid.PolicyQualifierUserNotice:
		if valueTag != cryptobyte_asn1.SEQUENCE {
			return PolicyQualifier{}, fmt.Errorf(
				"invalid userNotice in PolicyInformation %d: invalid UserNotice sequence",
				policyIndex,
			)
		}
		notice, err := decodeUserNotice(value)
		if err != nil {
			return PolicyQualifier{}, fmt.Errorf(
				"invalid userNotice in PolicyInformation %d: %w",
				policyIndex,
				err,
			)
		}
		decoded.Kind = PolicyQualifierUserNotice
		decoded.UserNotice = &notice

	default:
		decoded.Kind = PolicyQualifierUnknown
		decoded.Raw = value
	}
	return decoded, nil
}

func decodeUserNotice(notice cryptobyte.String) (UserNotice, error) {
	decoded := UserNotice{}
	if notice.PeekASN1Tag(cryptobyte_asn1.SEQUENCE) {
		reference, err := decodeNoticeReference(&notice)
		if err != nil {
			return UserNotice{}, err
		}
		decoded.Reference = &reference
	}

	if !notice.Empty() {
		explicitText, err := decodeDisplayText(&notice)
		if err != nil {
			return UserNotice{}, fmt.Errorf("invalid explicitText: %w", err)
		}
		decoded.ExplicitText = &explicitText
	}
	if !notice.Empty() {
		return UserNotice{}, fmt.Errorf("unexpected UserNotice data")
	}
	return decoded, nil
}

func decodeNoticeReference(notice *cryptobyte.String) (NoticeReference, error) {
	var encodedReference cryptobyte.String
	if !notice.ReadASN1(&encodedReference, cryptobyte_asn1.SEQUENCE) {
		return NoticeReference{}, fmt.Errorf("invalid NoticeReference")
	}

	organization, err := decodeDisplayText(&encodedReference)
	if err != nil {
		return NoticeReference{}, fmt.Errorf("invalid NoticeReference organization: %w", err)
	}

	var encodedNumbers cryptobyte.String
	if !encodedReference.ReadASN1(&encodedNumbers, cryptobyte_asn1.SEQUENCE) || !encodedReference.Empty() {
		return NoticeReference{}, fmt.Errorf("invalid NoticeReference numbers")
	}

	decoded := NoticeReference{Organization: organization}
	for !encodedNumbers.Empty() {
		var number int64
		if !encodedNumbers.ReadASN1Integer(&number) {
			return NoticeReference{}, fmt.Errorf("invalid notice number")
		}
		decoded.Numbers = append(decoded.Numbers, number)
	}
	return decoded, nil
}

func decodeDisplayText(input *cryptobyte.String) (DisplayText, error) {
	var value cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !input.ReadAnyASN1(&value, &tag) {
		return DisplayText{}, fmt.Errorf("missing DisplayText")
	}
	switch tag {
	case cryptobyte_asn1.UTF8String,
		cryptobyte_asn1.IA5String,
		cryptobyte_asn1.Tag(26), // VisibleString
		cryptobyte_asn1.Tag(30): // BMPString
	default:
		return DisplayText{}, fmt.Errorf("unsupported DisplayText tag %d", tag)
	}
	if value.Empty() {
		return DisplayText{}, fmt.Errorf("DisplayText must not be empty")
	}
	return DisplayText{Value: string(value), Tag: tag}, nil
}
