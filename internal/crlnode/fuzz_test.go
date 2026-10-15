package crlnode

import (
	"testing"

	"github.com/zmap/zcrypto/x509"

	"github.com/cavoq/PCL/internal/testpki"
	"github.com/cavoq/PCL/internal/x509ext"
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
		_, _ = x509ext.DecodeRevocationListStrict(list)
	})
}
