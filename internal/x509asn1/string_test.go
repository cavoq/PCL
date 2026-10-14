package x509asn1

import "testing"

func TestIsIA5String(t *testing.T) {
	if !IsIA5String("abc\x00\x7f") {
		t.Fatal("ASCII must be IA5")
	}
	if IsIA5String("caf\u00e9") || IsIA5String("\x80") {
		t.Fatal("characters above 0x7f are not IA5")
	}
}

func TestIsPrintableString(t *testing.T) {
	if !IsPrintableString("Ab1 '()+,-./:=?") {
		t.Fatal("PrintableString alphabet rejected")
	}
	for _, invalid := range []string{"&", "\x00", "a*b", "caf\u00e9", "@", "_", "!"} {
		if IsPrintableString(invalid) {
			t.Errorf("IsPrintableString(%q) = true", invalid)
		}
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

func TestDecodeDirectoryString(t *testing.T) {
	got, err := DecodeDirectoryString(12, []byte("party"))
	if err != nil || got != "party" {
		t.Fatalf("DecodeDirectoryString() = %q, %v; want party, nil", got, err)
	}
	for _, test := range []struct {
		name  string
		tag   int
		value []byte
	}{
		{name: "empty", tag: 12},
		{name: "IA5 is not DirectoryString", tag: 22, value: []byte("party")},
		{name: "invalid UTF-8", tag: 12, value: []byte{0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeDirectoryString(test.tag, test.value); err == nil {
				t.Fatal("expected invalid DirectoryString")
			}
		})
	}
}
