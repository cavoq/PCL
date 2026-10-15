package crl

import (
	"testing"

	"github.com/zmap/zcrypto/x509"

	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/testpki"
)

// FuzzBuildTree projects every CRL zcrypto accepts and decodes its
// extensions strictly.
func FuzzBuildTree(f *testing.F) {
	for _, seed := range testpki.SeedFiles(f, "tests/pkits/crls/*.crl", "tests/crls/*", "internal/crl/testdata/*.crl") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		list, err := x509.ParseRevocationList(der)
		if err != nil {
			return
		}
		if BuildTreeWithChain(list, nil) == nil {
			t.Fatal("BuildTreeWithChain returned no tree")
		}
		_, _ = crlzcrypto.DecodeRevocationListStrict(list)
	})
}
