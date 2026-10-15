package aia

import (
	"testing"

	"github.com/cavoq/PCL/internal/testpki"
)

// FuzzParseIssuerResponse covers CA Issuers responses: DER certificates,
// PKCS#7 bundles and their PEM forms.
func FuzzParseIssuerResponse(f *testing.F) {
	for _, seed := range testpki.SeedFiles(f, "tests/certs/*.pem") {
		f.Add(seed)
	}
	bundle, err := BuildCertsOnlyPKCS7(testpki.SeedFiles(f, "tests/certs/chain.pem")...)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bundle)
	f.Add(testpki.PEM("PKCS7", bundle))

	f.Fuzz(func(t *testing.T, data []byte) {
		certs, _, err := ParseIssuerResponse(data)
		if err == nil && len(certs) == 0 {
			t.Fatal("ParseIssuerResponse succeeded without certificates")
		}
	})
}
