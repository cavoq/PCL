package asn1

import "testing"

func TestParseUTCTime(t *testing.T) {
	der := make([]byte, 0, 15)
	der = append(der, 0x17, 0x0d)
	der = append(der, []byte("250101000000Z")...)

	info, err := ParseUTCTime(der)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsUTC {
		t.Fatal("expected UTC time")
	}
	if info.Tag != 23 {
		t.Fatalf("expected tag 23, got %d", info.Tag)
	}
	if info.RawString != "250101000000Z" {
		t.Fatalf("expected raw string, got %q", info.RawString)
	}
	if !info.HasZulu || !info.HasSeconds {
		t.Fatalf("expected Z suffix and seconds: %+v", info)
	}
}

func TestParseGeneralizedTime(t *testing.T) {
	der := make([]byte, 0, 19)
	der = append(der, 0x18, 0x11)
	der = append(der, []byte("20250101000000.5Z")...)

	info, err := ParseGeneralizedTime(der)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.IsUTC {
		t.Fatal("expected generalized time")
	}
	if info.Tag != 24 {
		t.Fatalf("expected tag 24, got %d", info.Tag)
	}
	if info.RawString != "20250101000000.5Z" {
		t.Fatalf("expected raw string, got %q", info.RawString)
	}
	if !info.HasZulu || !info.HasSeconds || !info.HasFraction {
		t.Fatalf("expected Z suffix, seconds, and fraction: %+v", info)
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
