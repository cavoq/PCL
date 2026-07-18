package asn1

import "testing"

func TestValidateIA5String(t *testing.T) {
	info, err := ValidateIA5String([]byte{0x16, 0x03, 'a', 'b', 'c'})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != EncodingIA5String || info.TagName != "IA5String" {
		t.Fatalf("unexpected encoding info: %+v", info)
	}
	if info.StringValue != "abc" || !info.ValidChars {
		t.Fatalf("unexpected string validation: %+v", info)
	}
}

func TestValidateIA5String_InvalidCharacter(t *testing.T) {
	info, err := ValidateIA5String([]byte{0x16, 0x01, 0x80})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ValidChars {
		t.Fatal("expected invalid IA5 character")
	}
	if len(info.InvalidChars) != 1 || info.InvalidChars[0] != 0x80 {
		t.Fatalf("unexpected invalid chars: %v", info.InvalidChars)
	}
}

func TestValidatePrintableString(t *testing.T) {
	info, err := ValidatePrintableString([]byte{0x13, 0x05, 'A', 'b', '1', ' ', '?'})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != EncodingPrintableString || info.StringValue != "Ab1 ?" || !info.ValidChars {
		t.Fatalf("unexpected printable string info: %+v", info)
	}
}

func TestValidatePrintableString_InvalidCharacter(t *testing.T) {
	info, err := ValidatePrintableString([]byte{0x13, 0x01, 0x00})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ValidChars {
		t.Fatal("expected invalid PrintableString character")
	}
}

func TestGetEncodingType(t *testing.T) {
	tests := map[int]EncodingType{
		22: EncodingIA5String,
		19: EncodingPrintableString,
		12: EncodingUTF8String,
		20: EncodingTeletexString,
		30: EncodingBMPString,
		28: EncodingUniversalString,
		99: EncodingUnknown,
	}
	for tag, want := range tests {
		if got := GetEncodingType(tag); got != want {
			t.Fatalf("tag %d: got %v, want %v", tag, got, want)
		}
	}
}

func TestStringTypeName(t *testing.T) {
	tests := map[int]string{
		12: "utf8String",
		19: "printableString",
		20: "teletexString",
		22: "ia5String",
		26: "visibleString",
		28: "universalString",
		30: "bmpString",
		13: "unknown",
	}
	for tag, want := range tests {
		if got := StringTypeName(tag); got != want {
			t.Fatalf("StringTypeName(%d) = %q, want %q", tag, got, want)
		}
	}
}

func TestValidatePrintableString_RejectsNonAlphabetCharacter(t *testing.T) {
	info, err := ValidatePrintableString([]byte{0x13, 0x01, '&'})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ValidChars {
		t.Fatal("ampersand is not part of the ASN.1 PrintableString alphabet")
	}
}
