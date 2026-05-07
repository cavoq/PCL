package asn1

import (
	stdasn1 "encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// TimeFormatInfo contains information about ASN.1 time encoding.
type TimeFormatInfo struct {
	Tag         int    // ASN.1 tag: 23 for UTCTime, 24 for GeneralizedTime
	Format      string // Time format string
	RawBytes    []byte // Raw DER bytes of the time value
	RawString   string // Raw string representation from DER
	IsUTC       bool   // true for UTCTime, false for GeneralizedTime
	HasSeconds  bool   // whether seconds are present
	HasFraction bool   // whether fractional seconds are present
	HasZulu     bool   // whether 'Z' suffix is present (required by RFC 5280)
}

// ParseUTCTime parses UTCTime DER bytes and returns format info.
// UTCTime format: YYMMDDHHMMSSZ (RFC 5280 requires Z suffix)
// Tag: 23 (0x17)
func ParseUTCTime(derBytes []byte) (*TimeFormatInfo, error) {
	valueBytes, err := readDERValue(derBytes, 23, "UTCTime")
	if err != nil {
		return nil, err
	}

	info := &TimeFormatInfo{
		Tag:        23,
		IsUTC:      true,
		RawBytes:   derBytes,
		RawString:  string(valueBytes),
		HasZulu:    strings.HasSuffix(string(valueBytes), "Z"),
		HasSeconds: len(valueBytes) >= 12,
	}

	var t time.Time
	rest, err := stdasn1.UnmarshalWithParams(derBytes, &t, "utctime")
	if err != nil {
		return nil, fmt.Errorf("failed to parse UTCTime: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in UTCTime")
	}

	return info, nil
}

// ParseGeneralizedTime parses GeneralizedTime DER bytes and returns format info.
// GeneralizedTime format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.fffZ
// Tag: 24 (0x18)
func ParseGeneralizedTime(derBytes []byte) (*TimeFormatInfo, error) {
	valueBytes, err := readDERValue(derBytes, 24, "GeneralizedTime")
	if err != nil {
		return nil, err
	}

	info := &TimeFormatInfo{
		Tag:         24,
		IsUTC:       false,
		RawBytes:    derBytes,
		RawString:   string(valueBytes),
		HasSeconds:  true,
		HasZulu:     strings.HasSuffix(string(valueBytes), "Z"),
		HasFraction: strings.Contains(string(valueBytes), "."),
	}

	var t time.Time
	rest, err := stdasn1.UnmarshalWithParams(derBytes, &t, "generalized")
	if err != nil {
		return nil, fmt.Errorf("failed to parse GeneralizedTime: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in GeneralizedTime")
	}

	return info, nil
}

func readDERValue(derBytes []byte, expectedTag int, name string) ([]byte, error) {
	if len(derBytes) < 2 {
		return nil, fmt.Errorf("invalid %s: too short", name)
	}

	tag := int(derBytes[0])
	if tag != expectedTag {
		return nil, fmt.Errorf("invalid %s tag: expected %d, got %d", name, expectedTag, tag)
	}

	length := int(derBytes[1])
	if len(derBytes) < 2+length {
		return nil, fmt.Errorf("invalid %s: length mismatch", name)
	}

	return derBytes[2 : 2+length], nil
}
