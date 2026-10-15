package cert

import (
	"bytes"
	"math/big"
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

// loadDSAInheritancePath loads PKITS Test5 target-first: the EE and its CA
// both inherit DSA parameters from the DSA CA below the trust anchor.
func loadDSAInheritancePath(t *testing.T) []*Info {
	t.Helper()
	var infos []*Info
	for _, file := range []string{
		"ValidDSAParameterInheritanceTest5EE.crt",
		"DSAParametersInheritedCACert.crt",
		"DSACACert.crt",
		"TrustAnchorRootCertificate.crt",
	} {
		infos = append(infos, loadPKITSCertificates(t, file)...)
	}
	return infos
}

func TestResolveInheritedDSAParameters(t *testing.T) {
	for name, order := range map[string][]int{
		"target first":  {0, 1, 2, 3},
		"issuers first": {3, 2, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			loaded := loadDSAInheritancePath(t)
			pool := make([]*Info, 0, len(order))
			for _, index := range order {
				pool = append(pool, loaded[index])
			}
			ResolveInheritedDSAParameters(pool)

			chain, err := BuildChainFor(loaded[:1], pool)
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
				parameters, ok := completeDSAParameters(chain[index].Cert)
				if !ok {
					t.Fatalf("certificate %d has no complete DSA parameters", index)
				}
				issuerParameters, _ := completeDSAParameters(chain[index+1].Cert)
				if !sameDSAParameters(parameters, issuerParameters) {
					t.Fatalf("certificate %d did not inherit its issuer's DSA parameters", index)
				}
			}
		})
	}
}

func TestResolveInheritedDSAParametersRequiresVerifyingSigner(t *testing.T) {
	loaded := loadDSAInheritancePath(t)
	inheritingCA, signer := loaded[1], loaded[2]
	signerParameters, _ := completeDSAParameters(signer.Cert)

	// The impostor has the signer's name and key identifier but different
	// parameters, so it cannot verify the inheriting CA's signature.
	impostorCert := *signer.Cert
	impostorParameters := dsa.Parameters{
		P: signerParameters.P,
		Q: signerParameters.Q,
		G: new(big.Int).Exp(signerParameters.G, big.NewInt(2), signerParameters.P),
	}
	impostorCert.PublicKey = &dsa.PublicKey{
		Parameters: impostorParameters,
		Y:          signer.Cert.PublicKey.(*dsa.PublicKey).Y,
	}
	impostor := &Info{Cert: &impostorCert}

	ResolveInheritedDSAParameters([]*Info{inheritingCA, impostor})
	if !hasInheritedDSAParameters(inheritingCA.Cert) {
		t.Fatal("parameters were taken from an issuer that does not verify the signature")
	}

	ResolveInheritedDSAParameters([]*Info{impostor, inheritingCA, signer})
	parameters, ok := completeDSAParameters(inheritingCA.Cert)
	if !ok || !sameDSAParameters(parameters, signerParameters) {
		t.Fatal("parameters were not taken from the verifying signer")
	}
}

func TestBuildChainForDoesNotResolveDSAParameters(t *testing.T) {
	loaded := loadDSAInheritancePath(t)
	if _, err := BuildChainFor(loaded[:1], loaded); err != nil {
		t.Fatal(err)
	}
	for _, info := range loaded[:2] {
		if !hasInheritedDSAParameters(info.Cert) {
			t.Fatalf("BuildChainFor changed the public key of %s", info.Cert.Subject)
		}
	}
}

func sameDSAParameters(a, b dsa.Parameters) bool {
	return a.P.Cmp(b.P) == 0 && a.Q.Cmp(b.Q) == 0 && a.G.Cmp(b.G) == 0
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
