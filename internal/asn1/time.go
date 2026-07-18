package asn1

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	UTCTimeTag         = int(cryptobyte_asn1.UTCTime)
	GeneralizedTimeTag = int(cryptobyte_asn1.GeneralizedTime)
)

// TimeEncoding contains the observable facts of one ASN.1 time value. RawDER
// includes the tag and length; RawValue is the encoded character content.
// Semantic date parsing remains with the owning certificate/CRL adapter so a
// non-conforming lexical form can still be projected and linted here.
type TimeEncoding struct {
	Tag         int
	RawDER      []byte
	RawValue    string
	HasSeconds  bool
	HasFraction bool
	HasZulu     bool
}

// ParseUTCTime parses UTCTime DER bytes and returns their encoding facts.
// UTCTime format: YYMMDDHHMMSSZ (RFC 5280 requires Z suffix)
// Tag: 23 (0x17)
func ParseUTCTime(derBytes []byte) (*TimeEncoding, error) {
	return parseTimeEncoding(derBytes, cryptobyte_asn1.UTCTime, "UTCTime", 12)
}

// ParseGeneralizedTime parses GeneralizedTime DER bytes and returns their
// encoding facts.
// GeneralizedTime format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.fffZ
// Tag: 24 (0x18)
func ParseGeneralizedTime(derBytes []byte) (*TimeEncoding, error) {
	return parseTimeEncoding(derBytes, cryptobyte_asn1.GeneralizedTime, "GeneralizedTime", 14)
}

func parseTimeEncoding(
	derBytes []byte,
	tag cryptobyte_asn1.Tag,
	name string,
	secondsLength int,
) (*TimeEncoding, error) {
	valueBytes, err := readDERValue(derBytes, int(tag), name)
	if err != nil {
		return nil, err
	}

	value := string(valueBytes)
	timePart := valueWithoutZone(value)
	fractionAt := strings.IndexAny(timePart, ".,")
	if fractionAt >= 0 {
		timePart = timePart[:fractionAt]
	}

	return &TimeEncoding{
		Tag:         int(tag),
		RawDER:      append([]byte(nil), derBytes...),
		RawValue:    value,
		HasSeconds:  len(timePart) >= secondsLength,
		HasFraction: fractionAt >= 0,
		HasZulu:     strings.HasSuffix(value, "Z"),
	}, nil
}

func valueWithoutZone(value string) string {
	if strings.HasSuffix(value, "Z") {
		return value[:len(value)-1]
	}
	if len(value) >= 5 {
		zoneAt := len(value) - 5
		if value[zoneAt] == '+' || value[zoneAt] == '-' {
			return value[:zoneAt]
		}
	}
	return value
}

func readDERValue(derBytes []byte, expectedTag int, name string) ([]byte, error) {
	input := cryptobyte.String(derBytes)
	var value cryptobyte.String
	if !input.ReadASN1(&value, cryptobyte_asn1.Tag(expectedTag)) || !input.Empty() {
		return nil, fmt.Errorf("invalid %s DER", name)
	}
	return value, nil
}
