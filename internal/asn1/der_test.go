package asn1

import (
	stdasn1 "encoding/asn1"
	"testing"
)

func TestEncodeOctetString(t *testing.T) {
	got := EncodeOctetString([]byte{0x01, 0x02})
	want := []byte{0x04, 0x02, 0x01, 0x02}
	if string(got) != string(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestEncodeSequence(t *testing.T) {
	got := EncodeSequence([]byte{0x05, 0x00})
	want := []byte{0x30, 0x02, 0x05, 0x00}
	if string(got) != string(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestEncodeContextSpecificConstructed(t *testing.T) {
	got := EncodeContextSpecificConstructed(2, []byte{0x30, 0x00})
	want := []byte{0xA2, 0x02, 0x30, 0x00}
	if string(got) != string(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestEncodeObjectIdentifier(t *testing.T) {
	got, err := EncodeObjectIdentifier(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02}
	if string(got) != string(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestReadDERLength(t *testing.T) {
	length, contentStart, err := ReadDERLength([]byte{0x30, 0x82, 0x01, 0x00}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 256 || contentStart != 4 {
		t.Fatalf("got length=%d contentStart=%d", length, contentStart)
	}
}
