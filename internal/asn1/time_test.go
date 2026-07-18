package asn1

import (
	"bytes"
	"testing"
)

func TestParseUTCTimeEncodingFacts(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		hasSeconds  bool
		hasFraction bool
		hasZulu     bool
	}{
		{name: "seconds and Z", value: "250101000000Z", hasSeconds: true, hasZulu: true},
		{name: "minutes and Z", value: "2501010000Z", hasZulu: true},
		{name: "seconds and offset", value: "250101000000+0100", hasSeconds: true},
		{name: "minutes and offset", value: "2501010000+0100"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der := encodeTestTime(23, test.value)
			info, err := ParseUTCTime(der)
			if err != nil {
				t.Fatalf("parse UTCTime: %v", err)
			}
			assertTimeEncoding(
				t,
				info,
				23,
				der,
				test.value,
				test.hasSeconds,
				test.hasFraction,
				test.hasZulu,
			)
		})
	}
}

func TestParseGeneralizedTimeEncodingFacts(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		hasSeconds  bool
		hasFraction bool
		hasZulu     bool
	}{
		{name: "seconds and Z", value: "20250101000000Z", hasSeconds: true, hasZulu: true},
		{name: "minutes and Z", value: "202501010000Z", hasZulu: true},
		{name: "seconds and offset", value: "20250101000000+0100", hasSeconds: true},
		{name: "fraction", value: "20250101000000.5Z", hasSeconds: true, hasFraction: true, hasZulu: true},
		{name: "comma fraction", value: "20250101000000,5Z", hasSeconds: true, hasFraction: true, hasZulu: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der := encodeTestTime(24, test.value)
			info, err := ParseGeneralizedTime(der)
			if err != nil {
				t.Fatalf("parse GeneralizedTime: %v", err)
			}
			assertTimeEncoding(
				t,
				info,
				24,
				der,
				test.value,
				test.hasSeconds,
				test.hasFraction,
				test.hasZulu,
			)
		})
	}
}

func TestParseTimeEncodingOwnsRawDER(t *testing.T) {
	der := encodeTestTime(23, "250101000000Z")
	want := append([]byte(nil), der...)
	info, err := ParseUTCTime(der)
	if err != nil {
		t.Fatalf("parse UTCTime: %v", err)
	}

	der[2] = '9'
	if !bytes.Equal(info.RawDER, want) {
		t.Fatalf("RawDER changed with input: got %x, want %x", info.RawDER, want)
	}
}

func TestReadDERValueErrors(t *testing.T) {
	if _, err := readDERValue([]byte{0x17}, 23, "UTCTime"); err == nil {
		t.Fatal("expected too short error")
	}
	if _, err := readDERValue([]byte{0x18, 0x00}, 23, "UTCTime"); err == nil {
		t.Fatal("expected wrong tag error")
	}
	if _, err := readDERValue([]byte{0x17, 0x02, '1'}, 23, "UTCTime"); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

func encodeTestTime(tag byte, value string) []byte {
	return append([]byte{tag, byte(len(value))}, []byte(value)...)
}

func assertTimeEncoding(
	t *testing.T,
	info *TimeEncoding,
	tag int,
	rawDER []byte,
	rawValue string,
	hasSeconds bool,
	hasFraction bool,
	hasZulu bool,
) {
	t.Helper()
	if info.Tag != tag || info.RawValue != rawValue || !bytes.Equal(info.RawDER, rawDER) ||
		info.HasSeconds != hasSeconds || info.HasFraction != hasFraction || info.HasZulu != hasZulu {
		t.Fatalf("unexpected time encoding: %+v", info)
	}
}
