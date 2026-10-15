package x509asn1

import (
	stdasn1 "encoding/asn1"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cavoq/PCL/internal/testpki"
)

func seedCertificates(t testing.TB) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, der := range testpki.SeedFiles(t, "tests/pkits/certs/*.crt", "tests/certs/*.pem") {
		if cert, err := x509.ParseCertificate(der); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

// FuzzNamesMatch checks that name comparison is reflexive and symmetric
// besides not panicking, and that subtree containment holds for equal names.
func FuzzNamesMatch(f *testing.F) {
	for _, cert := range seedCertificates(f) {
		f.Add(cert.RawSubject, cert.RawIssuer)
	}
	f.Fuzz(func(t *testing.T, left, right []byte) {
		if !NamesMatch(left, left) {
			t.Fatalf("name %x does not match itself", left)
		}
		if NamesMatch(left, right) != NamesMatch(right, left) {
			t.Fatalf("NamesMatch(%x, %x) is not symmetric", left, right)
		}
		if _, err := ParseDistinguishedNameStrict(left); err == nil && !NameWithinSubtree(left, left) {
			t.Fatalf("name %x is not within its own subtree", left)
		}
		_ = NameWithinSubtree(left, right)
	})
}

// FuzzAlgorithmIdentifierParams covers AlgorithmIdentifier parameters, alone
// and as the signature algorithm of a signed object.
func FuzzAlgorithmIdentifierParams(f *testing.F) {
	for _, cert := range seedCertificates(f) {
		f.Add(cert.Raw)
		signed := cryptobyte.String(cert.Raw)
		var contents, tbs, algorithm cryptobyte.String
		if signed.ReadASN1(&contents, cryptobyte_asn1.SEQUENCE) &&
			contents.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) &&
			contents.ReadASN1Element(&algorithm, cryptobyte_asn1.SEQUENCE) {
			f.Add([]byte(algorithm))
		}
	}
	f.Fuzz(func(_ *testing.T, der []byte) {
		_ = ParseAlgorithmIDParams(der)
		_, _ = ParseAlgorithmIDParamsStrict(der)
		_ = ParseSignedObjectAlgorithmParams(der)
		_, _ = ParseSignedObjectAlgorithmParamsStrict(der)
	})
}

func FuzzTime(f *testing.F) {
	moment := time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
	for _, params := range []string{"utc", "generalized"} {
		der, err := stdasn1.MarshalWithParams(moment, params)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	f.Fuzz(func(_ *testing.T, der []byte) {
		_, _ = ParseUTCTime(der)
		_, _ = ParseGeneralizedTime(der)
	})
}

func FuzzDecodeDirectoryString(f *testing.F) {
	for _, tag := range []int{stdasn1.TagUTF8String, stdasn1.TagPrintableString, stdasn1.TagIA5String, stdasn1.TagBMPString, 28, stdasn1.TagT61String} {
		f.Add(tag, []byte("Example CA"))
	}
	f.Fuzz(func(_ *testing.T, tag int, value []byte) {
		_, _ = DecodeDirectoryString(tag, value)
	})
}

func FuzzReadDERLength(f *testing.F) {
	f.Add([]byte{0x30, 0x82, 0x01, 0x00}, 1)
	f.Add([]byte{0x30, 0x05}, 1)
	f.Fuzz(func(t *testing.T, data []byte, position int) {
		length, next, err := ReadDERLength(data, position)
		if err == nil && (length < 0 || next < 0 || next > len(data)) {
			t.Fatalf("ReadDERLength = %d, %d for %d bytes", length, next, len(data))
		}
	})
}
