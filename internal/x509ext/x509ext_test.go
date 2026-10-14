package x509ext

import (
	"testing"

	"github.com/cavoq/PCL/internal/x509asn1"
)

func TestDecodeNonNegativeIntegerBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		der     []byte
		want    string
		wantErr bool
	}{
		{name: "zero", der: []byte{0x02, 0x01, 0x00}, want: "0"},
		{
			name: "larger than native integer",
			der:  []byte{0x02, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: "18446744073709551616",
		},
		{name: "negative", der: []byte{0x02, 0x01, 0xff}, wantErr: true},
		{name: "redundant leading zero", der: []byte{0x02, 0x02, 0x00, 0x7f}, wantErr: true},
		{name: "trailing data", der: []byte{0x02, 0x01, 0x00, 0x00}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeNonNegativeInteger(test.der)
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeNonNegativeInteger() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got.Decimal != test.want {
				t.Fatalf("decimal = %q, want %q", got.Decimal, test.want)
			}
			if test.name == "larger than native integer" && got.FitsInt {
				t.Fatal("unbounded INTEGER was truncated to native int")
			}
		})
	}
}

func TestDecodeReasonFlagsCanonicalDER(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
		wantMask ReasonMask
		wantErr  bool
	}{
		{name: "empty", contents: []byte{0x00}},
		{name: "key compromise", contents: []byte{0x06, 0x40}, wantMask: ReasonKeyCompromise},
		{name: "wire bit eight", contents: []byte{0x07, 0x00, 0x80}, wantMask: ReasonAACompromise},
		{name: "trailing zero bit", contents: []byte{0x06, 0x80}, wantErr: true},
		{name: "undefined bit nine", contents: []byte{0x06, 0x00, 0x40}, wantErr: true},
		{name: "nonzero unused bit", contents: []byte{0x07, 0x01}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeReasonFlagsContents(test.contents)
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeReasonFlagsContents() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got.Mask != test.wantMask {
				t.Fatalf("mask = %#x, want %#x", got.Mask, test.wantMask)
			}
		})
	}
}

func TestReasonFlagDescriptorsAreCanonicalAndImmutable(t *testing.T) {
	wantNames := [...]string{
		"unused",
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"privilegeWithdrawn",
		"aACompromise",
	}

	descriptors := ReasonFlagDescriptors()
	var definedReasons ReasonMask
	for bit, descriptor := range descriptors {
		if descriptor.Bit != bit {
			t.Errorf("descriptor %d bit = %d", bit, descriptor.Bit)
		}
		if descriptor.Mask != ReasonMask(1)<<bit {
			t.Errorf("descriptor %d mask = %#x", bit, descriptor.Mask)
		}
		if descriptor.CanonicalName != wantNames[bit] {
			t.Errorf("descriptor %d name = %q, want %q", bit, descriptor.CanonicalName, wantNames[bit])
		}
		if bit != 0 {
			definedReasons |= descriptor.Mask
		}
	}
	if definedReasons != AllReasons {
		t.Fatalf("descriptor reasons = %#x, AllReasons = %#x", definedReasons, AllReasons)
	}

	descriptors[0].CanonicalName = "changed"
	if got := ReasonFlagDescriptors()[0].CanonicalName; got != "unused" {
		t.Fatalf("descriptor mutation escaped returned copy: %q", got)
	}
}

func TestDecodeGeneralNamesOwnsInputAndRejectsMalformedIA5(t *testing.T) {
	der := []byte{0x30, 0x0a, 0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'a'}
	names, err := DecodeGeneralNames(der)
	if err != nil {
		t.Fatalf("DecodeGeneralNames(): %v", err)
	}
	der[4] = 'X'
	if got := string(names[0].RawValue); got != "http://a" {
		t.Fatalf("decoded URI changed with input: %q", got)
	}
	if _, err := DecodeGeneralNames([]byte{0x30, 0x03, 0x82, 0x01, 0xff}); err == nil {
		t.Fatal("non-IA5 dNSName was accepted")
	}
	if _, err := DecodeGeneralNames([]byte{0x30, 0x00}); err == nil {
		t.Fatal("empty GeneralNames was accepted")
	}
}

func TestDecodeDistributionPointsFullAndRelative(t *testing.T) {
	fullDER := []byte{
		0x30, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0xa0, 0x0a,
		0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'a',
	}
	points, err := DecodeDistributionPoints(fullDER)
	if err != nil {
		t.Fatalf("decode fullName: %v", err)
	}
	if len(points) != 1 || points[0].Name == nil ||
		points[0].Name.Kind != DistributionPointNameFullName {
		t.Fatalf("fullName points = %#v", points)
	}
	if uris := DistributionPointURIs(points); len(uris) != 1 || uris[0] != "http://a" {
		t.Fatalf("DistributionPointURIs() = %#v", uris)
	}

	relativeDER := []byte{
		0x30, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0xa1, 0x0a,
		0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 'x',
	}
	relative, err := DecodeDistributionPoints(relativeDER)
	if err != nil {
		t.Fatalf("decode relative name: %v", err)
	}
	if relative[0].Name.Kind != DistributionPointNameRelative {
		t.Fatalf("relative kind = %q", relative[0].Name.Kind)
	}
	baseName := []byte{
		0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x0c, 0x04, 'b', 'a', 's', 'e',
	}
	expanded, err := ExpandDistributionPointName(relative[0].Name, baseName)
	if err != nil {
		t.Fatalf("expand relative name: %v", err)
	}
	parsed, err := x509asn1.ParseDistinguishedNameStrict(expanded[0].RawValue)
	if err != nil || len(parsed.RDNs) != 2 {
		t.Fatalf("expanded Name = %#v, err %v", parsed, err)
	}
	if !DistributionPointNamesIntersect(relative[0].Name, relative[0].Name, baseName, baseName) {
		t.Fatal("same relative names and bases did not intersect")
	}
}

func TestDecodeDistributionPointsRejectsMalformedFields(t *testing.T) {
	tests := [][]byte{
		{0x30, 0x00},             // empty outer sequence
		{0x30, 0x02, 0x30, 0x00}, // point has no name or issuer
		// Duplicate reasons fields.
		{0x30, 0x0a, 0x30, 0x08, 0x81, 0x02, 0x06, 0x40, 0x81, 0x02, 0x06, 0x40},
	}
	for _, der := range tests {
		if _, err := DecodeDistributionPoints(der); err == nil {
			t.Fatalf("malformed DistributionPoints accepted: %x", der)
		}
	}
}
