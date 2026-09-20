package x509ext

import "fmt"

// ReasonMask represents the eight revocation reasons carried by ReasonFlags.
// Bit positions match the ReasonFlags wire positions (1 through 8). This type
// is deliberately distinct from the CRLReason ENUMERATED entry extension,
// where value 8 means removeFromCRL rather than aACompromise.
type ReasonMask uint16

const (
	reasonUnused             ReasonMask = 1 << 0
	ReasonKeyCompromise      ReasonMask = 1 << 1
	ReasonCACompromise       ReasonMask = 1 << 2
	ReasonAffiliationChanged ReasonMask = 1 << 3
	ReasonSuperseded         ReasonMask = 1 << 4
	ReasonCessation          ReasonMask = 1 << 5
	ReasonCertificateHold    ReasonMask = 1 << 6
	ReasonPrivilegeWithdrawn ReasonMask = 1 << 7
	ReasonAACompromise       ReasonMask = 1 << 8
	AllReasons                          = ReasonKeyCompromise |
		ReasonCACompromise |
		ReasonAffiliationChanged |
		ReasonSuperseded |
		ReasonCessation |
		ReasonCertificateHold |
		ReasonPrivilegeWithdrawn |
		ReasonAACompromise
)

// ReasonFlagDescriptor binds an RFC 5280 wire bit to its mask and canonical
// projection name. Bit zero is included because it is structurally decodable,
// although profile validation rejects it as the unused bit.
type ReasonFlagDescriptor struct {
	Bit           int
	Mask          ReasonMask
	CanonicalName string
}

// ReasonFlagDescriptorCount is fixed by the ReasonFlags ASN.1 definition:
// one unused bit followed by eight defined revocation reasons.
const ReasonFlagDescriptorCount = 9

var reasonFlagDescriptors = [ReasonFlagDescriptorCount]ReasonFlagDescriptor{
	{Bit: 0, Mask: reasonUnused, CanonicalName: "unused"},
	{Bit: 1, Mask: ReasonKeyCompromise, CanonicalName: "keyCompromise"},
	{Bit: 2, Mask: ReasonCACompromise, CanonicalName: "cACompromise"},
	{Bit: 3, Mask: ReasonAffiliationChanged, CanonicalName: "affiliationChanged"},
	{Bit: 4, Mask: ReasonSuperseded, CanonicalName: "superseded"},
	{Bit: 5, Mask: ReasonCessation, CanonicalName: "cessationOfOperation"},
	{Bit: 6, Mask: ReasonCertificateHold, CanonicalName: "certificateHold"},
	{Bit: 7, Mask: ReasonPrivilegeWithdrawn, CanonicalName: "privilegeWithdrawn"},
	{Bit: 8, Mask: ReasonAACompromise, CanonicalName: "aACompromise"},
}

// ReasonFlagDescriptors returns the fixed canonical descriptor set by value,
// so callers cannot mutate the package's shared metadata.
func ReasonFlagDescriptors() [ReasonFlagDescriptorCount]ReasonFlagDescriptor {
	return reasonFlagDescriptors
}

type ReasonFlags struct {
	Mask       ReasonMask
	RawDER     []byte
	Value      []byte
	UnusedBits int
}

// DecodeReasonFlagsContents decodes the contents octets of an implicitly
// tagged ReasonFlags BIT STRING. Empty flags are structurally representable;
// profile semantics decide whether they are useful.
func DecodeReasonFlagsContents(encoded []byte) (ReasonFlags, error) {
	if len(encoded) == 1 {
		if encoded[0] != 0 {
			return ReasonFlags{}, fmt.Errorf("invalid ReasonFlags BIT STRING")
		}
		return ReasonFlags{RawDER: append([]byte(nil), encoded...)}, nil
	}
	if len(encoded) < 2 || encoded[0] > 7 ||
		encoded[len(encoded)-1]&byte((1<<encoded[0])-1) != 0 {
		return ReasonFlags{}, fmt.Errorf("invalid ReasonFlags BIT STRING")
	}

	unusedBits := int(encoded[0])
	value := append([]byte(nil), encoded[1:]...)
	bitLength := len(value)*8 - unusedBits
	if bitLength > ReasonFlagDescriptorCount || !reasonFlagSet(value, bitLength-1) {
		return ReasonFlags{}, fmt.Errorf("invalid ReasonFlags BIT STRING")
	}

	var mask ReasonMask
	for _, descriptor := range reasonFlagDescriptors {
		if descriptor.Bit < bitLength && reasonFlagSet(value, descriptor.Bit) {
			mask |= descriptor.Mask
		}
	}
	return ReasonFlags{
		Mask:       mask,
		RawDER:     append([]byte(nil), encoded...),
		Value:      value,
		UnusedBits: unusedBits,
	}, nil
}

func reasonFlagSet(value []byte, bit int) bool {
	if bit < 0 {
		return false
	}
	byteIndex := bit / 8
	bitIndex := 7 - bit%8
	return byteIndex < len(value) && value[byteIndex]&(1<<bitIndex) != 0
}
