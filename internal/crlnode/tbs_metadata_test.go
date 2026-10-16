package crlnode

import (
	"testing"

	"github.com/cavoq/PCL/internal/x509asn1"
)

func TestParseTBSCertListMetadata(t *testing.T) {
	der := func(tag byte, content ...byte) []byte { return append([]byte{tag, byte(len(content))}, content...) }
	join := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	algorithm := der(0x30, der(0x06, 0x2a, 0x03)...)
	issuer := der(0x30)
	utc := der(0x17, []byte("260718110000Z")...)
	generalized := der(0x18, []byte("20500101000000Z")...)
	entry := der(0x30, join(der(0x02, 0x2a), der(0x17, []byte("2607181000Z")...))...)

	metadata, err := parseTBSCertListMetadata(der(0x30, join(
		der(0x02, 0x01), algorithm, issuer, utc, generalized, der(0x30, entry...),
	)...))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ThisUpdate.Tag != x509asn1.UTCTimeTag || metadata.NextUpdate == nil ||
		metadata.NextUpdate.Tag != x509asn1.GeneralizedTimeTag {
		t.Errorf("times = %+v, %+v", metadata.ThisUpdate, metadata.NextUpdate)
	}
	if len(metadata.RevocationDates) != 1 || metadata.RevocationDates[0].HasSeconds {
		t.Errorf("revocationDates = %+v, want one without seconds", metadata.RevocationDates)
	}

	// Without version and nextUpdate, the entries follow thisUpdate.
	metadata, err = parseTBSCertListMetadata(der(0x30, join(algorithm, issuer, utc, der(0x30, entry...))...))
	if err != nil || metadata.NextUpdate != nil || len(metadata.RevocationDates) != 1 {
		t.Errorf("v1 without nextUpdate = %+v, %v", metadata, err)
	}

	if _, err := parseTBSCertListMetadata(der(0x30, join(algorithm, issuer, der(0x04))...)); err == nil {
		t.Error("an OCTET STRING thisUpdate was accepted")
	}
}
