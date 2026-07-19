package zcrypto

import (
	stdasn1 "encoding/asn1"
	"fmt"

	"github.com/cavoq/PCL/internal/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type decodedCertificatePolicies struct {
	Policies []decodedPolicyInformation
	RawDER   []byte
}

type decodedPolicyInformation struct {
	OID        string
	Qualifiers []decodedPolicyQualifier
}

type policyQualifierKind uint8

const (
	unknownPolicyQualifier policyQualifierKind = iota
	cpsPolicyQualifier
	userNoticePolicyQualifier
)

type decodedPolicyQualifier struct {
	OID        string
	Kind       policyQualifierKind
	CPSURI     string
	UserNotice *decodedUserNotice
	Raw        cryptobyte.String
}

type decodedUserNotice struct {
	Reference    *decodedNoticeReference
	ExplicitText *decodedDisplayText
}

type decodedNoticeReference struct {
	Organization decodedDisplayText
	Numbers      []int64
}

type decodedDisplayText struct {
	Value string
	Tag   cryptobyte_asn1.Tag
}

func decodeCertificatePolicies(extValue []byte) (decodedCertificatePolicies, error) {
	input := cryptobyte.String(extValue)
	var encodedPolicies cryptobyte.String
	if !input.ReadASN1(&encodedPolicies, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return decodedCertificatePolicies{}, fmt.Errorf("invalid CertificatePolicies sequence")
	}
	if encodedPolicies.Empty() {
		return decodedCertificatePolicies{}, fmt.Errorf("CertificatePolicies must not be empty")
	}

	decoded := decodedCertificatePolicies{RawDER: append([]byte(nil), extValue...)}
	seenPolicyIdentifiers := make(map[string]struct{})
	for policyIndex := 0; !encodedPolicies.Empty(); policyIndex++ {
		policy, err := decodePolicyInformation(&encodedPolicies, policyIndex)
		if err != nil {
			return decodedCertificatePolicies{}, err
		}
		if _, duplicate := seenPolicyIdentifiers[policy.OID]; duplicate {
			return decodedCertificatePolicies{}, fmt.Errorf(
				"duplicate policyIdentifier %s in PolicyInformation %d",
				policy.OID,
				policyIndex,
			)
		}
		if policy.OID == oid.AnyPolicy {
			for _, qualifier := range policy.Qualifiers {
				if qualifier.Kind == unknownPolicyQualifier {
					return decodedCertificatePolicies{}, fmt.Errorf(
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

func decodePolicyInformation(input *cryptobyte.String, policyIndex int) (decodedPolicyInformation, error) {
	var encodedPolicy cryptobyte.String
	if !input.ReadASN1(&encodedPolicy, cryptobyte_asn1.SEQUENCE) {
		return decodedPolicyInformation{}, fmt.Errorf("invalid PolicyInformation %d", policyIndex)
	}

	var policyID stdasn1.ObjectIdentifier
	if !encodedPolicy.ReadASN1ObjectIdentifier(&policyID) {
		return decodedPolicyInformation{}, fmt.Errorf("invalid policyIdentifier in PolicyInformation %d", policyIndex)
	}
	decoded := decodedPolicyInformation{OID: policyID.String()}
	if encodedPolicy.Empty() {
		return decoded, nil
	}

	var encodedQualifiers cryptobyte.String
	if !encodedPolicy.ReadASN1(&encodedQualifiers, cryptobyte_asn1.SEQUENCE) ||
		!encodedPolicy.Empty() || encodedQualifiers.Empty() {
		return decodedPolicyInformation{}, fmt.Errorf("invalid policyQualifiers in PolicyInformation %d", policyIndex)
	}

	for qualifierIndex := 0; !encodedQualifiers.Empty(); qualifierIndex++ {
		qualifier, err := decodePolicyQualifier(&encodedQualifiers, policyIndex, qualifierIndex)
		if err != nil {
			return decodedPolicyInformation{}, err
		}
		decoded.Qualifiers = append(decoded.Qualifiers, qualifier)
	}
	return decoded, nil
}

func decodePolicyQualifier(input *cryptobyte.String, policyIndex, qualifierIndex int) (decodedPolicyQualifier, error) {
	var encodedQualifier cryptobyte.String
	if !input.ReadASN1(&encodedQualifier, cryptobyte_asn1.SEQUENCE) {
		return decodedPolicyQualifier{}, fmt.Errorf(
			"invalid PolicyQualifierInfo %d in PolicyInformation %d",
			qualifierIndex,
			policyIndex,
		)
	}

	var qualifierID stdasn1.ObjectIdentifier
	if !encodedQualifier.ReadASN1ObjectIdentifier(&qualifierID) {
		return decodedPolicyQualifier{}, fmt.Errorf("invalid policyQualifierId in PolicyInformation %d", policyIndex)
	}

	var value cryptobyte.String
	var valueTag cryptobyte_asn1.Tag
	if !encodedQualifier.ReadAnyASN1(&value, &valueTag) || !encodedQualifier.Empty() {
		return decodedPolicyQualifier{}, fmt.Errorf("invalid qualifier value in PolicyInformation %d", policyIndex)
	}

	decoded := decodedPolicyQualifier{OID: qualifierID.String()}
	switch decoded.OID {
	case oid.PolicyQualifierCPS:
		if valueTag != cryptobyte_asn1.IA5String {
			return decodedPolicyQualifier{}, fmt.Errorf(
				"CPS qualifier in PolicyInformation %d is not IA5String",
				policyIndex,
			)
		}
		if value.Empty() {
			return decodedPolicyQualifier{}, fmt.Errorf("invalid CPS qualifier in PolicyInformation %d", policyIndex)
		}
		for _, character := range value {
			if character > 0x7f {
				return decodedPolicyQualifier{}, fmt.Errorf(
					"non-IA5 character in CPS qualifier in PolicyInformation %d",
					policyIndex,
				)
			}
		}
		decoded.Kind = cpsPolicyQualifier
		decoded.CPSURI = string(value)

	case oid.PolicyQualifierUserNotice:
		if valueTag != cryptobyte_asn1.SEQUENCE {
			return decodedPolicyQualifier{}, fmt.Errorf(
				"invalid userNotice in PolicyInformation %d: invalid UserNotice sequence",
				policyIndex,
			)
		}
		notice, err := decodeUserNotice(value)
		if err != nil {
			return decodedPolicyQualifier{}, fmt.Errorf(
				"invalid userNotice in PolicyInformation %d: %w",
				policyIndex,
				err,
			)
		}
		decoded.Kind = userNoticePolicyQualifier
		decoded.UserNotice = &notice

	default:
		decoded.Kind = unknownPolicyQualifier
		decoded.Raw = value
	}
	return decoded, nil
}

func decodeUserNotice(notice cryptobyte.String) (decodedUserNotice, error) {
	decoded := decodedUserNotice{}
	if notice.PeekASN1Tag(cryptobyte_asn1.SEQUENCE) {
		reference, err := decodeNoticeReference(&notice)
		if err != nil {
			return decodedUserNotice{}, err
		}
		decoded.Reference = &reference
	}

	if !notice.Empty() {
		explicitText, err := decodeDisplayText(&notice)
		if err != nil {
			return decodedUserNotice{}, fmt.Errorf("invalid explicitText: %w", err)
		}
		decoded.ExplicitText = &explicitText
	}
	if !notice.Empty() {
		return decodedUserNotice{}, fmt.Errorf("unexpected UserNotice data")
	}
	return decoded, nil
}

func decodeNoticeReference(notice *cryptobyte.String) (decodedNoticeReference, error) {
	var encodedReference cryptobyte.String
	if !notice.ReadASN1(&encodedReference, cryptobyte_asn1.SEQUENCE) {
		return decodedNoticeReference{}, fmt.Errorf("invalid NoticeReference")
	}

	organization, err := decodeDisplayText(&encodedReference)
	if err != nil {
		return decodedNoticeReference{}, fmt.Errorf("invalid NoticeReference organization: %w", err)
	}

	var encodedNumbers cryptobyte.String
	if !encodedReference.ReadASN1(&encodedNumbers, cryptobyte_asn1.SEQUENCE) || !encodedReference.Empty() {
		return decodedNoticeReference{}, fmt.Errorf("invalid NoticeReference numbers")
	}

	decoded := decodedNoticeReference{Organization: organization}
	for !encodedNumbers.Empty() {
		var number int64
		if !encodedNumbers.ReadASN1Integer(&number) {
			return decodedNoticeReference{}, fmt.Errorf("invalid notice number")
		}
		decoded.Numbers = append(decoded.Numbers, number)
	}
	return decoded, nil
}

func decodeDisplayText(input *cryptobyte.String) (decodedDisplayText, error) {
	var value cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !input.ReadAnyASN1(&value, &tag) {
		return decodedDisplayText{}, fmt.Errorf("missing DisplayText")
	}
	switch tag {
	case cryptobyte_asn1.UTF8String,
		cryptobyte_asn1.IA5String,
		cryptobyte_asn1.Tag(26), // VisibleString
		cryptobyte_asn1.Tag(30): // BMPString
	default:
		return decodedDisplayText{}, fmt.Errorf("unsupported DisplayText tag %d", tag)
	}
	if value.Empty() {
		return decodedDisplayText{}, fmt.Errorf("DisplayText must not be empty")
	}
	return decodedDisplayText{Value: string(value), Tag: tag}, nil
}
