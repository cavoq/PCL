package x509ext

import (
	"testing"

	"github.com/zmap/zcrypto/x509"
	"golang.org/x/crypto/cryptobyte"

	"github.com/cavoq/PCL/internal/oid"
	"github.com/cavoq/PCL/internal/testpki"
)

// extensionSeeds returns the values of the identified extensions in the
// seed certificates.
func extensionSeeds(t testing.TB, identifiers ...string) [][]byte {
	var values [][]byte
	for _, der := range testpki.SeedFiles(t, "tests/pkits/certs/*.crt", "tests/certs/*.pem") {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		for _, extension := range cert.Extensions {
			for _, identifier := range identifiers {
				if extension.Id.String() == identifier {
					values = append(values, extension.Value)
				}
			}
		}
	}
	return values
}

func FuzzDecodeGeneralNames(f *testing.F) {
	for _, seed := range extensionSeeds(f, oid.SubjectAlternativeName, oid.IssuerAlternativeName) {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, der []byte) {
		_, _ = DecodeGeneralNames(der)
		input := cryptobyte.String(der)
		_, _ = ReadNameConstraintGeneralName(&input)
	})
}

func FuzzDecodeDistributionPoints(f *testing.F) {
	for _, seed := range extensionSeeds(f, oid.CRLDistributionPoints, oid.FreshestCRL) {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, der []byte) {
		points, err := DecodeDistributionPoints(der)
		if err != nil {
			return
		}
		_ = DistributionPointURIs(points)
		for _, point := range points {
			_, _ = ExpandDistributionPointName(point.Name, []byte{0x30, 0x00})
		}
	})
}

func FuzzDecodeReasonFlags(f *testing.F) {
	f.Add([]byte{0x07, 0x80})
	f.Add([]byte{0x01, 0x7f, 0x80})
	f.Fuzz(func(_ *testing.T, encoded []byte) {
		_, _ = DecodeReasonFlagsContents(encoded)
	})
}

func FuzzDecodeNonNegativeInteger(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x00})
	f.Add([]byte{0x02, 0x02, 0x00, 0x80})
	f.Fuzz(func(_ *testing.T, der []byte) {
		_, _ = DecodeNonNegativeInteger(der)
		_, _ = DecodeRegisteredID(der)
	})
}
