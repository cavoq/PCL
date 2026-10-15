package cert

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/zmap/zcrypto/dsa"

	"github.com/cavoq/PCL/internal/certparse"
)

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
	if !certparse.HasInheritedDSAParameters(inheritingCA.Cert) {
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
		if !certparse.HasInheritedDSAParameters(info.Cert) {
			t.Fatalf("BuildChainFor changed the public key of %s", info.Cert.Subject)
		}
	}
}

func sameDSAParameters(a, b dsa.Parameters) bool {
	return a.P.Cmp(b.P) == 0 && a.Q.Cmp(b.Q) == 0 && a.G.Cmp(b.G) == 0
}

func loadPKITSCertificates(t *testing.T, file string) []*Info {
	t.Helper()
	certificates, err := LoadCertificates(filepath.Join("..", "..", "tests", "pkits", "certs", file), nil)
	if err != nil {
		t.Fatal(err)
	}
	return certificates
}
