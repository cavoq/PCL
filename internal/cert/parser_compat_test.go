package cert

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/zmap/zcrypto/dsa"

	"github.com/cavoq/PCL/internal/x509ext"
)

func TestParseCertificates_PKITSCompatibility(t *testing.T) {
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
			certificates, _, err := ParseCertificates(der)
			if err != nil {
				t.Fatal(err)
			}
			if len(certificates) != 1 {
				t.Fatalf("parsed %d certificates, want 1", len(certificates))
			}
			certificate := certificates[0]
			if !bytes.Equal(certificate.Raw, der) {
				t.Fatal("parsed certificate did not preserve the original DER")
			}

			if test.inheritedDSA {
				publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
				if !ok || publicKey.Y == nil || !hasInheritedDSAParameters(certificate) {
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

func TestParseCertificates_CompatibilityRejectsMalformedCRLDP(t *testing.T) {
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
	if _, _, err := ParseCertificates(der); err == nil {
		t.Fatal("malformed CRL distribution point was accepted by the compatibility parser")
	}
}

func TestBuildChainFor_ResolvesInheritedDSAParameters(t *testing.T) {
	targets := loadPKITSCertificates(t, "ValidDSAParameterInheritanceTest5EE.crt")
	pool := append([]*Info(nil), targets...)
	for _, file := range []string{
		"TrustAnchorRootCertificate.crt",
		"DSACACert.crt",
		"DSAParametersInheritedCACert.crt",
	} {
		pool = append(pool, loadPKITSCertificates(t, file)...)
	}

	chain, err := BuildChainFor(targets, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 4 {
		t.Fatalf("chain has %d certificates, want 4", len(chain))
	}
	for index := 0; index < len(chain)-1; index++ {
		if err := CheckSignatureFrom(chain[index].Cert, chain[index+1].Cert); err != nil {
			t.Fatalf("certificate %d signature: %v", index, err)
		}
	}
	for index := 0; index < 2; index++ {
		if hasInheritedDSAParameters(chain[index].Cert) {
			t.Fatalf("certificate %d still has unresolved DSA parameters", index)
		}
		parameters, ok := completeDSAParameters(chain[index].Cert)
		if !ok {
			t.Fatalf("certificate %d has no complete DSA parameters", index)
		}
		issuerParameters, ok := completeDSAParameters(chain[index+1].Cert)
		if !ok || parameters.P.Cmp(issuerParameters.P) != 0 ||
			parameters.Q.Cmp(issuerParameters.Q) != 0 || parameters.G.Cmp(issuerParameters.G) != 0 {
			t.Fatalf("certificate %d did not inherit its issuer's DSA parameters", index)
		}
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

func loadPKITSCertificates(t *testing.T, file string) []*Info {
	t.Helper()
	certificates, err := LoadCertificates(filepath.Join("..", "..", "tests", "pkits", "certs", file), nil)
	if err != nil {
		t.Fatal(err)
	}
	return certificates
}
