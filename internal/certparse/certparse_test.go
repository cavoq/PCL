package certparse

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/zmap/zcrypto/dsa"

	"github.com/cavoq/PCL/internal/x509ext"
)

func TestParseCertificatePKITSCompatibility(t *testing.T) {
	tests := []struct {
		file         string
		inheritedDSA bool
		crlDP        bool
	}{
		{file: "DSAParametersInheritedCACert.crt", inheritedDSA: true},
		{file: "ValidDSAParameterInheritanceTest5EE.crt", inheritedDSA: true},
		{file: "ValiddistributionPointTest4EE.crt", crlDP: true},
		{file: "ValiddistributionPointTest5EE.crt", crlDP: true},
		{file: "ValidcRLIssuerTest29EE.crt", crlDP: true},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			der := readPKITSCertificate(t, test.file)
			certificate, err := ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(certificate.Raw, der) {
				t.Fatal("parsed certificate did not preserve the original DER")
			}

			if test.inheritedDSA {
				publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
				if !ok || publicKey.Y == nil || !HasInheritedDSAParameters(certificate) {
					t.Fatalf("public key = %#v, want unresolved inherited DSA parameters", certificate.PublicKey)
				}
			}
			if test.crlDP {
				extension, ok := certificate.ExtensionsMap[crlDistributionPointsOID.String()]
				if !ok {
					t.Fatal("restored certificate has no CRL distribution points extension")
				}
				if _, err := x509ext.DecodeDistributionPoints(extension.Value); err != nil {
					t.Fatalf("strictly decode restored CRL distribution points: %v", err)
				}
				if _, ok := certificate.ExtensionsMap[maskedCRLDistributionPointsOID.String()]; ok {
					t.Fatal("temporary compatibility OID escaped into the parsed certificate")
				}
			}
		})
	}
}

func TestParseCertificateRejectsMalformedCRLDP(t *testing.T) {
	der := readPKITSCertificate(t, "ValiddistributionPointTest4EE.crt")
	der = append([]byte(nil), der...)
	encodedRelativeName := []byte{0xa0, 0x28, 0xa1, 0x26, 0x30, 0x24}
	offset := bytes.Index(der, encodedRelativeName)
	if offset < 0 {
		t.Fatal("fixture does not contain the expected relative distribution point")
	}
	// Change the RelativeDistinguishedName's SEQUENCE to a SET. The zcrypto
	// projection still fails, but the compatibility path must also reject it
	// rather than hiding an encoding PCL's decoder did not accept.
	der[offset+4] = 0x31
	if _, err := ParseCertificate(der); err == nil {
		t.Fatal("malformed CRL distribution point was accepted by the compatibility parser")
	}
}

func readPKITSCertificate(t *testing.T, file string) []byte {
	t.Helper()
	der, err := os.ReadFile(filepath.Join("..", "..", "tests", "pkits", "certs", file))
	if err != nil {
		t.Fatal(err)
	}
	return der
}
