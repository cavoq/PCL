package zcrypto

import (
	"testing"

	"golang.org/x/crypto/ocsp"

	"github.com/cavoq/PCL/internal/testpki"
)

// FuzzParseResponse runs the raw OCSP decoders on any input and projects
// every response golang.org/x/crypto/ocsp accepts.
func FuzzParseResponse(f *testing.F) {
	for _, seed := range testpki.SeedFiles(f, "tests/ocsps/*.ocsp", "tests/ocsps/*/*.ocsp") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ParseNonceFromRaw(raw)
		_, _ = ParseCertID(raw)
		_ = ParseOCSPSignatureAlgorithmParams(raw)

		response, err := ocsp.ParseResponse(raw, nil)
		if err != nil {
			return
		}
		if BuildTree(response) == nil {
			t.Fatal("BuildTree returned no tree")
		}
	})
}
